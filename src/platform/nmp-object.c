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

#include "nm-default.h"

#include "nmp-object.h"

#include <unistd.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <libudev.h>

#include "nm-utils.h"
#include "nm-glib-aux/nm-secret-utils.h"

#include "nm-core-utils.h"
#include "nm-platform-utils.h"

#include "wifi/nm-wifi-utils.h"
#include "wpan/nm-wpan-utils.h"

/*****************************************************************************/

#define _NMLOG_DOMAIN LOGD_PLATFORM
#define _NMLOG(level, obj, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        \
        if (nm_logging_enabled (__level, _NMLOG_DOMAIN)) { \
            const NMPObject *const __obj = (obj); \
            \
            _nm_log (__level, _NMLOG_DOMAIN, 0, NULL, NULL, \
                     "nmp-object[%p/%s]: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     __obj, \
                     (__obj ? NMP_OBJECT_GET_CLASS (__obj)->obj_type_name : "???") \
                     _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*****************************************************************************/

typedef struct {
	NMDedupMultiIdxType parent;
	NMPCacheIdType cache_id_type;
} DedupMultiIdxType;

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

	NMDedupMultiIndex *multi_idx;

	/* an idx_type entry for each NMP_CACHE_ID_TYPE. Note that NONE (zero)
	 * is skipped, so the index is shifted by one: idx_type[cache_id_type - 1].
	 *
	 * Don't bother, use _idx_type_get() instead! */
	DedupMultiIdxType idx_types[NMP_CACHE_ID_TYPE_MAX];

	gboolean use_udev;
};

/*****************************************************************************/

int
nm_sock_addr_union_cmp (const NMSockAddrUnion *a, const NMSockAddrUnion *b)
{
	nm_assert (!a || NM_IN_SET (a->sa.sa_family, AF_UNSPEC, AF_INET, AF_INET6));
	nm_assert (!b || NM_IN_SET (b->sa.sa_family, AF_UNSPEC, AF_INET, AF_INET6));

	NM_CMP_SELF (a, b);

	NM_CMP_FIELD (a, b, sa.sa_family);
	switch (a->sa.sa_family) {
	case AF_INET:
		NM_CMP_DIRECT (ntohl (a->in.sin_addr.s_addr), ntohl (b->in.sin_addr.s_addr));
		NM_CMP_DIRECT (htons (a->in.sin_port), htons (b->in.sin_port));
		break;
	case AF_INET6:
		NM_CMP_DIRECT_IN6ADDR (&a->in6.sin6_addr, &b->in6.sin6_addr);
		NM_CMP_DIRECT (htons (a->in6.sin6_port), htons (b->in6.sin6_port));
		NM_CMP_FIELD (a, b, in6.sin6_scope_id);
		NM_CMP_FIELD (a, b, in6.sin6_flowinfo);
		break;
	}
	return 0;
}

void
nm_sock_addr_union_hash_update (const NMSockAddrUnion *a, NMHashState *h)
{
	if (!a) {
		nm_hash_update_val (h, 1241364739u);
		return;
	}

	nm_assert (NM_IN_SET (a->sa.sa_family, AF_UNSPEC, AF_INET, AF_INET6));

	switch (a->sa.sa_family) {
	case AF_INET:
		nm_hash_update_vals (h,
		                     a->in.sin_family,
		                     a->in.sin_addr.s_addr,
		                     a->in.sin_port);
		return;
	case AF_INET6:
		nm_hash_update_vals (h,
		                     a->in6.sin6_family,
		                     a->in6.sin6_addr,
		                     a->in6.sin6_port,
		                     a->in6.sin6_scope_id,
		                     a->in6.sin6_flowinfo);
		return;
	default:
		nm_hash_update_val (h, a->sa.sa_family);
		return;
	}
}

/**
 * nm_sock_addr_union_cpy:
 * @dst: the destination #NMSockAddrUnion. It will always be fully initialized,
 *   to one of the address families AF_INET, AF_INET6, or AF_UNSPEC (in case of
 *   error).
 * @src: (allow-none): the source buffer with an sockaddr to copy. It may be unaligned in
 *   memory. If not %NULL, the buffer must be at least large enough to contain
 *   sa.sa_family, and then, depending on sa.sa_family, it must be large enough
 *   to hold struct sockaddr_in or struct sockaddr_in6.
 *
 * @dst will always be fully initialized (including setting all un-used bytes to zero).
 */
void
nm_sock_addr_union_cpy (NMSockAddrUnion *dst,
                        gconstpointer src /* unaligned (const NMSockAddrUnion *) */)
{
	struct sockaddr sa;
	gsize src_len;

	nm_assert (dst);

	*dst = (NMSockAddrUnion) NM_SOCK_ADDR_UNION_INIT_UNSPEC;

	if (!src)
		return;

	memcpy (&sa.sa_family, &((struct sockaddr *) src)->sa_family, sizeof (sa.sa_family));

	if (sa.sa_family == AF_INET)
		src_len = sizeof (struct sockaddr_in);
	else if (sa.sa_family == AF_INET6)
		src_len = sizeof (struct sockaddr_in6);
	else
		return;

	memcpy (dst, src, src_len);
	nm_assert (dst->sa.sa_family == sa.sa_family);
}

/**
 * nm_sock_addr_union_cpy_untrusted:
 * @dst: the destination #NMSockAddrUnion. It will always be fully initialized,
 *   to one of the address families AF_INET, AF_INET6, or AF_UNSPEC (in case of
 *   error).
 * @src: the source buffer with an sockaddr to copy. It may be unaligned in
 *   memory.
 * @src_len: the length of @src in bytes.
 *
 * The function requires @src_len to be either sizeof(struct sockaddr_in) or sizeof (struct sockaddr_in6).
 * If that's the case, then @src will be interpreted as such structure (unaligned), and
 * accessed. It will check sa.sa_family to match the expected sizes, and if it does, the
 * struct will be copied.
 *
 * On any failure, @dst will be set to sa.sa_family AF_UNSPEC.
 * @dst will always be fully initialized (including setting all un-used bytes to zero).
 */
void
nm_sock_addr_union_cpy_untrusted (NMSockAddrUnion *dst,
                                  gconstpointer src /* unaligned (const NMSockAddrUnion *) */,
                                  gsize src_len)
{
	int f_expected;
	struct sockaddr sa;

	nm_assert (dst);

	*dst = (NMSockAddrUnion) NM_SOCK_ADDR_UNION_INIT_UNSPEC;

	if (src_len == sizeof (struct sockaddr_in))
		f_expected = AF_INET;
	else if (src_len == sizeof (struct sockaddr_in6))
		f_expected = AF_INET6;
	else
		return;

	memcpy (&sa.sa_family, &((struct sockaddr *) src)->sa_family, sizeof (sa.sa_family));

	if (sa.sa_family != f_expected)
		return;

	memcpy (dst, src, src_len);
	nm_assert (dst->sa.sa_family == sa.sa_family);
}

const char *
nm_sock_addr_union_to_string (const NMSockAddrUnion *sa,
                              char *buf,
                              gsize len)
{
	char s_addr[NM_UTILS_INET_ADDRSTRLEN];
	char s_scope_id[40];

	if (!nm_utils_to_string_buffer_init_null (sa, &buf, &len))
		return buf;

	/* maybe we should use getnameinfo(), but here implement it ourself.
	 *
	 * We want to see the actual bytes for debugging (as we understand them),
	 * and now what getnameinfo() makes of it. Also, it's simpler this way. */

	switch (sa->sa.sa_family) {
	case AF_INET:
		g_snprintf (buf, len,
		            "%s:%u",
		            nm_utils_inet4_ntop (sa->in.sin_addr.s_addr, s_addr),
		            (guint) htons (sa->in.sin_port));
		break;
	case AF_INET6:
		g_snprintf (buf, len,
		            "[%s%s]:%u",
		            nm_utils_inet6_ntop (&sa->in6.sin6_addr, s_addr),
		            (  sa->in6.sin6_scope_id != 0
		             ? nm_sprintf_buf (s_scope_id, "%u", sa->in6.sin6_scope_id)
		             : ""),
		            (guint) htons (sa->in6.sin6_port));
		break;
	case AF_UNSPEC:
		g_snprintf (buf, len, "unspec");
		break;
	default:
		g_snprintf (buf, len,
		            "{addr-family:%u}",
		            (unsigned) sa->sa.sa_family);
		break;
	}

	return buf;
}

/*****************************************************************************/

static const NMDedupMultiIdxTypeClass _dedup_multi_idx_type_class;

static void
_idx_obj_id_hash_update (const NMDedupMultiIdxType *idx_type,
                         const NMDedupMultiObj *obj,
                         NMHashState *h)
{
	const NMPObject *o = (NMPObject *) obj;

	nm_assert (idx_type && idx_type->klass == &_dedup_multi_idx_type_class);
	nm_assert (NMP_OBJECT_GET_TYPE (o) != NMP_OBJECT_TYPE_UNKNOWN);

	nmp_object_id_hash_update (o, h);
}

static gboolean
_idx_obj_id_equal (const NMDedupMultiIdxType *idx_type,
                   const NMDedupMultiObj *obj_a,
                   const NMDedupMultiObj *obj_b)
{
	const NMPObject *o_a = (NMPObject *) obj_a;
	const NMPObject *o_b = (NMPObject *) obj_b;

	nm_assert (idx_type && idx_type->klass == &_dedup_multi_idx_type_class);
	nm_assert (NMP_OBJECT_GET_TYPE (o_a) != NMP_OBJECT_TYPE_UNKNOWN);
	nm_assert (NMP_OBJECT_GET_TYPE (o_b) != NMP_OBJECT_TYPE_UNKNOWN);

	return nmp_object_id_equal (o_a, o_b);
}

static guint
_idx_obj_part (const DedupMultiIdxType *idx_type,
               const NMPObject *obj_a,
               const NMPObject *obj_b,
               NMHashState *h)
{
	NMPObjectType obj_type;

	/* the hash/equals functions are strongly related. So, keep them
	 * side-by-side and do it all in _idx_obj_part(). */

	nm_assert (idx_type);
	nm_assert (idx_type->parent.klass == &_dedup_multi_idx_type_class);
	nm_assert (obj_a);
	nm_assert (NMP_OBJECT_GET_TYPE (obj_a) != NMP_OBJECT_TYPE_UNKNOWN);
	nm_assert (!obj_b || (NMP_OBJECT_GET_TYPE (obj_b) != NMP_OBJECT_TYPE_UNKNOWN));
	nm_assert (!h || !obj_b);

	switch (idx_type->cache_id_type) {

	case NMP_CACHE_ID_TYPE_OBJECT_TYPE:
		if (obj_b)
			return NMP_OBJECT_GET_TYPE (obj_a) == NMP_OBJECT_GET_TYPE (obj_b);
		if (h) {
			nm_hash_update_vals (h,
			                     idx_type->cache_id_type,
			                     NMP_OBJECT_GET_TYPE (obj_a));
		}
		return 1;

	case NMP_CACHE_ID_TYPE_LINK_BY_IFNAME:
		if (NMP_OBJECT_GET_TYPE (obj_a) != NMP_OBJECT_TYPE_LINK) {
			/* first check, whether obj_a is suitable for this idx_type.
			 * If not, return 0 (which is correct for partitionable(), hash() and equal()
			 * functions. */
			if (h)
				nm_hash_update_val (h, obj_a);
			return 0;
		}
		if (obj_b) {
			/* we are in equal() mode. Compare obj_b with obj_a. */
			return    NMP_OBJECT_GET_TYPE (obj_b) == NMP_OBJECT_TYPE_LINK
			       && nm_streq (obj_a->link.name, obj_b->link.name);
		}
		if (h) {
			nm_hash_update_val (h, idx_type->cache_id_type);
			nm_hash_update_strarr (h, obj_a->link.name);
		}
		/* just return 1, to indicate that obj_a is partitionable by this idx_type. */
		return 1;

	case NMP_CACHE_ID_TYPE_DEFAULT_ROUTES:
		if (   !NM_IN_SET (NMP_OBJECT_GET_TYPE (obj_a), NMP_OBJECT_TYPE_IP4_ROUTE,
		                                                NMP_OBJECT_TYPE_IP6_ROUTE)
		    || !NM_PLATFORM_IP_ROUTE_IS_DEFAULT (&obj_a->ip_route)
		    || !nmp_object_is_visible (obj_a)) {
			if (h)
				nm_hash_update_val (h, obj_a);
			return 0;
		}
		if (obj_b) {
			return    NMP_OBJECT_GET_TYPE (obj_a) == NMP_OBJECT_GET_TYPE (obj_b)
			       && NM_PLATFORM_IP_ROUTE_IS_DEFAULT (&obj_b->ip_route)
			       && nmp_object_is_visible (obj_b);
		}
		if (h) {
			nm_hash_update_vals (h,
			                     idx_type->cache_id_type,
			                     NMP_OBJECT_GET_TYPE (obj_a));
		}
		return 1;

	case NMP_CACHE_ID_TYPE_OBJECT_BY_IFINDEX:
		if (   !NM_IN_SET (NMP_OBJECT_GET_TYPE (obj_a), NMP_OBJECT_TYPE_IP4_ADDRESS,
		                                                NMP_OBJECT_TYPE_IP6_ADDRESS,
		                                                NMP_OBJECT_TYPE_IP4_ROUTE,
		                                                NMP_OBJECT_TYPE_IP6_ROUTE,
		                                                NMP_OBJECT_TYPE_QDISC,
		                                                NMP_OBJECT_TYPE_TFILTER)
		    || !nmp_object_is_visible (obj_a)) {
			if (h)
				nm_hash_update_val (h, obj_a);
			return 0;
		}
		nm_assert (NMP_OBJECT_CAST_OBJ_WITH_IFINDEX (obj_a)->ifindex > 0);
		if (obj_b) {
			return    NMP_OBJECT_GET_TYPE (obj_a) == NMP_OBJECT_GET_TYPE (obj_b)
			       && NMP_OBJECT_CAST_OBJ_WITH_IFINDEX (obj_a)->ifindex == NMP_OBJECT_CAST_OBJ_WITH_IFINDEX (obj_b)->ifindex
			       && nmp_object_is_visible (obj_b);
		}
		if (h) {
			nm_hash_update_vals (h,
			                     idx_type->cache_id_type,
			                     obj_a->obj_with_ifindex.ifindex);
		}
		return 1;

	case NMP_CACHE_ID_TYPE_ROUTES_BY_WEAK_ID:
		obj_type = NMP_OBJECT_GET_TYPE (obj_a);
		if (   !NM_IN_SET (obj_type, NMP_OBJECT_TYPE_IP4_ROUTE,
		                             NMP_OBJECT_TYPE_IP6_ROUTE)
		    || NMP_OBJECT_CAST_IP_ROUTE (obj_a)->ifindex <= 0) {
			if (h)
				nm_hash_update_val (h, obj_a);
			return 0;
		}
		if (obj_b) {
			return    obj_type == NMP_OBJECT_GET_TYPE (obj_b)
			       && NMP_OBJECT_CAST_IP_ROUTE (obj_b)->ifindex > 0
			       && (obj_type == NMP_OBJECT_TYPE_IP4_ROUTE
			           ? (nm_platform_ip4_route_cmp (&obj_a->ip4_route, &obj_b->ip4_route, NM_PLATFORM_IP_ROUTE_CMP_TYPE_WEAK_ID) == 0)
			           : (nm_platform_ip6_route_cmp (&obj_a->ip6_route, &obj_b->ip6_route, NM_PLATFORM_IP_ROUTE_CMP_TYPE_WEAK_ID) == 0));
		}
		if (h) {
			nm_hash_update_val (h, idx_type->cache_id_type);
			if (obj_type == NMP_OBJECT_TYPE_IP4_ROUTE)
				nm_platform_ip4_route_hash_update (&obj_a->ip4_route, NM_PLATFORM_IP_ROUTE_CMP_TYPE_WEAK_ID, h);
			else
				nm_platform_ip6_route_hash_update (&obj_a->ip6_route, NM_PLATFORM_IP_ROUTE_CMP_TYPE_WEAK_ID, h);
		}
		return 1;

	case NMP_CACHE_ID_TYPE_OBJECT_BY_ADDR_FAMILY:
		obj_type = NMP_OBJECT_GET_TYPE (obj_a);
		/* currently, only routing rules are supported for this cache-id-type. */
		if (   obj_type != NMP_OBJECT_TYPE_ROUTING_RULE
		    || !NM_IN_SET (obj_a->routing_rule.addr_family, AF_INET, AF_INET6)) {
			if (h)
				nm_hash_update_val (h, obj_a);
			return 0;
		}
		if (obj_b) {
			return    NMP_OBJECT_GET_TYPE (obj_b) == NMP_OBJECT_TYPE_ROUTING_RULE
			       && obj_a->routing_rule.addr_family == obj_b->routing_rule.addr_family;
		}
		if (h) {
			nm_hash_update_vals (h, idx_type->cache_id_type,
			                        obj_a->routing_rule.addr_family);
		}
		return 1;

	case NMP_CACHE_ID_TYPE_NONE:
	case __NMP_CACHE_ID_TYPE_MAX:
		break;
	}
	nm_assert_not_reached ();
	return 0;
}

static gboolean
_idx_obj_partitionable (const NMDedupMultiIdxType *idx_type,
                        const NMDedupMultiObj *obj)
{
	return _idx_obj_part ((DedupMultiIdxType *) idx_type,
	                      (NMPObject *) obj,
	                      NULL,
	                      NULL) != 0;
}

static void
_idx_obj_partition_hash_update (const NMDedupMultiIdxType *idx_type,
                                const NMDedupMultiObj *obj,
                                NMHashState *h)
{
	_idx_obj_part ((DedupMultiIdxType *) idx_type,
	               (NMPObject *) obj,
	               NULL,
	               h);
}

static gboolean
_idx_obj_partition_equal (const NMDedupMultiIdxType *idx_type,
                          const NMDedupMultiObj *obj_a,
                          const NMDedupMultiObj *obj_b)
{
	return _idx_obj_part ((DedupMultiIdxType *) idx_type,
	                      (NMPObject *) obj_a,
	                      (NMPObject *) obj_b,
	                      NULL);
}

static const NMDedupMultiIdxTypeClass _dedup_multi_idx_type_class = {
	.idx_obj_id_hash_update = _idx_obj_id_hash_update,
	.idx_obj_id_equal = _idx_obj_id_equal,
	.idx_obj_partitionable = _idx_obj_partitionable,
	.idx_obj_partition_hash_update = _idx_obj_partition_hash_update,
	.idx_obj_partition_equal = _idx_obj_partition_equal,
};

static void
_dedup_multi_idx_type_init (DedupMultiIdxType *idx_type, NMPCacheIdType cache_id_type)
{
	nm_dedup_multi_idx_type_init ((NMDedupMultiIdxType *) idx_type,
	                              &_dedup_multi_idx_type_class);
	idx_type->cache_id_type = cache_id_type;
}

/*****************************************************************************/

static void
_vlan_xgress_qos_mappings_hash_update (guint n_map,
                                       const NMVlanQosMapping *map,
                                       NMHashState *h)
{
	/* ensure no padding. */
	G_STATIC_ASSERT (sizeof (NMVlanQosMapping) == 2 * sizeof (guint32));

	nm_hash_update_val (h, n_map);
	if (n_map)
		nm_hash_update (h, map, n_map * sizeof (*map));
}

static int
_vlan_xgress_qos_mappings_cmp (guint n_map,
                               const NMVlanQosMapping *map1,
                               const NMVlanQosMapping *map2)
{
	guint i;

	for (i = 0; i < n_map; i++) {
		if (map1[i].from != map2[i].from)
			return map1[i].from < map2[i].from ? -1 : 1;
		if (map1[i].to != map2[i].to)
			return map1[i].to < map2[i].to ? -1 : 1;
	}
	return 0;
}

static void
_vlan_xgress_qos_mappings_cpy (guint *dst_n_map,
                               NMVlanQosMapping **dst_map,
                               guint src_n_map,
                               const NMVlanQosMapping *src_map)
{
	if (src_n_map == 0) {
		g_clear_pointer (dst_map, g_free);
		*dst_n_map = 0;
	} else if (   src_n_map != *dst_n_map
	           || _vlan_xgress_qos_mappings_cmp (src_n_map, *dst_map, src_map) != 0) {
		g_clear_pointer (dst_map, g_free);
		*dst_n_map = src_n_map;
		if (src_n_map > 0)
			*dst_map = nm_memdup (src_map, sizeof (*src_map) * src_n_map);
	}
}

/*****************************************************************************/

static void
_wireguard_allowed_ip_hash_update (const NMPWireGuardAllowedIP *ip,
                                   NMHashState *h)
{
	nm_hash_update_vals (h, ip->family,
	                        ip->mask);

	if (ip->family == AF_INET)
		nm_hash_update_val (h, ip->addr.addr4);
	else if (ip->family == AF_INET6)
		nm_hash_update_val (h, ip->addr.addr6);
}

static int
_wireguard_allowed_ip_cmp (const NMPWireGuardAllowedIP *a,
                           const NMPWireGuardAllowedIP *b)
{
	NM_CMP_SELF (a, b);

	NM_CMP_FIELD (a, b, family);
	NM_CMP_FIELD (a, b, mask);

	if (a->family == AF_INET)
		NM_CMP_FIELD (a, b, addr.addr4);
	else if (a->family == AF_INET6)
		NM_CMP_FIELD_IN6ADDR (a, b, addr.addr6);

	return 0;
}

static void
_wireguard_peer_hash_update (const NMPWireGuardPeer *peer,
                             NMHashState *h)
{
	guint i;

	nm_hash_update (h, peer->public_key, sizeof (peer->public_key));
	nm_hash_update (h, peer->preshared_key, sizeof (peer->preshared_key));
	nm_hash_update_vals (h,
	                     peer->persistent_keepalive_interval,
	                     peer->allowed_ips_len,
	                     peer->rx_bytes,
	                     peer->tx_bytes,
	                     peer->last_handshake_time.tv_sec,
	                     peer->last_handshake_time.tv_nsec);

	nm_sock_addr_union_hash_update (&peer->endpoint, h);

	for (i = 0; i < peer->allowed_ips_len; i++)
		_wireguard_allowed_ip_hash_update (&peer->allowed_ips[i], h);
}

static int
_wireguard_peer_cmp (const NMPWireGuardPeer *a,
                     const NMPWireGuardPeer *b)
{
	guint i;

	NM_CMP_SELF (a, b);

	NM_CMP_FIELD (a, b, last_handshake_time.tv_sec);
	NM_CMP_FIELD (a, b, last_handshake_time.tv_nsec);
	NM_CMP_FIELD (a, b, rx_bytes);
	NM_CMP_FIELD (a, b, tx_bytes);
	NM_CMP_FIELD (a, b, allowed_ips_len);
	NM_CMP_FIELD (a, b, persistent_keepalive_interval);
	NM_CMP_FIELD (a, b, endpoint.sa.sa_family);
	NM_CMP_FIELD_MEMCMP (a, b, public_key);
	NM_CMP_FIELD_MEMCMP (a, b, preshared_key);

	NM_CMP_RETURN (nm_sock_addr_union_cmp (&a->endpoint, &b->endpoint));

	for (i = 0; i < a->allowed_ips_len; i++) {
		NM_CMP_RETURN (_wireguard_allowed_ip_cmp (&a->allowed_ips[i],
		                                          &b->allowed_ips[i]));
	}

	return 0;
}

/*****************************************************************************/

static const char *
_link_get_driver (struct udev_device *udevice, const char *kind, int ifindex)
{
	const char *driver = NULL;

	nm_assert (kind == g_intern_string (kind));

	if (udevice) {
		driver = nmp_utils_udev_get_driver (udevice);
		if (driver)
			return driver;
	}

	if (kind)
		return kind;

	if (ifindex > 0) {
		NMPUtilsEthtoolDriverInfo driver_info;

		if (nmp_utils_ethtool_get_driver_info (ifindex, &driver_info)) {
			if (driver_info.driver[0])
				return g_intern_string (driver_info.driver);
		}
	}

	return "unknown";
}

void
_nmp_object_fixup_link_udev_fields (NMPObject **obj_new, NMPObject *obj_orig, gboolean use_udev)
{
	const char *driver = NULL;
	gboolean initialized = FALSE;
	NMPObject *obj;

	nm_assert (obj_orig || *obj_new);
	nm_assert (obj_new);
	nm_assert (!obj_orig || NMP_OBJECT_GET_TYPE (obj_orig) == NMP_OBJECT_TYPE_LINK);
	nm_assert (!*obj_new || NMP_OBJECT_GET_TYPE (*obj_new) == NMP_OBJECT_TYPE_LINK);

	obj = *obj_new ?: obj_orig;

	/* The link contains internal fields that are combined by
	 * properties from netlink and udev. Update those properties */

	/* When a link is not in netlink, its udev fields don't matter. */
	if (obj->_link.netlink.is_in_netlink) {
		driver = _link_get_driver (obj->_link.udev.device,
		                           obj->link.kind,
		                           obj->link.ifindex);
		if (obj->_link.udev.device)
			initialized = TRUE;
		else if (!use_udev) {
			/* If we don't use udev, we immediately mark the link as initialized.
			 *
			 * For that, we consult @use_udev argument, that is cached via
			 * nmp_cache_use_udev_get(). It is on purpose not to test
			 * for a writable /sys on every call. A minor reason for that is
			 * performance, but the real reason is reproducibility.
			 * */
			initialized = TRUE;
		}
	}

	if (   nm_streq0 (obj->link.driver, driver)
	    && obj->link.initialized == initialized)
		return;

	if (!*obj_new)
		obj = *obj_new = nmp_object_clone (obj, FALSE);

	obj->link.driver = driver;
	obj->link.initialized = initialized;
}

static void
_nmp_object_fixup_link_master_connected (NMPObject **obj_new, NMPObject *obj_orig, const NMPCache *cache)
{
	NMPObject *obj;

	nm_assert (obj_orig || *obj_new);
	nm_assert (obj_new);
	nm_assert (!obj_orig || NMP_OBJECT_GET_TYPE (obj_orig) == NMP_OBJECT_TYPE_LINK);
	nm_assert (!*obj_new || NMP_OBJECT_GET_TYPE (*obj_new) == NMP_OBJECT_TYPE_LINK);

	obj = *obj_new ?: obj_orig;

	if (nmp_cache_link_connected_needs_toggle (cache, obj, NULL, NULL)) {
		if (!*obj_new)
			obj = *obj_new = nmp_object_clone (obj, FALSE);
		obj->link.connected = !obj->link.connected;
	}
}

/*****************************************************************************/

static void
_vt_cmd_obj_dispose_link (NMPObject *obj)
{
	if (obj->_link.udev.device) {
		udev_device_unref (obj->_link.udev.device);
		obj->_link.udev.device = NULL;
	}
	g_clear_object (&obj->_link.ext_data);
	nmp_object_unref (obj->_link.netlink.lnk);
}

static void
_vt_cmd_obj_dispose_lnk_vlan (NMPObject *obj)
{
	g_free ((gpointer) obj->_lnk_vlan.ingress_qos_map);
	g_free ((gpointer) obj->_lnk_vlan.egress_qos_map);
}

static void
_wireguard_clear (NMPObjectLnkWireGuard *lnk)
{
	guint i;

	nm_explicit_bzero (lnk->_public.private_key,
	                   sizeof (lnk->_public.private_key));
	for (i = 0; i < lnk->peers_len; i++) {
		NMPWireGuardPeer *peer = (NMPWireGuardPeer *) &lnk->peers[i];

		nm_explicit_bzero (peer->preshared_key, sizeof (peer->preshared_key));
	}
	g_free ((gpointer) lnk->peers);
	g_free ((gpointer) lnk->_allowed_ips_buf);
}

static void
_vt_cmd_obj_dispose_lnk_wireguard (NMPObject *obj)
{
	_wireguard_clear (&obj->_lnk_wireguard);
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
	obj->parent._ref_count = 1;
	return obj;
}

NMPObject *
nmp_object_new (NMPObjectType obj_type, gconstpointer plobj)
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

/*****************************************************************************/

static void
_nmp_object_stackinit_from_class (NMPObject *obj, const NMPClass *klass)
{
	nm_assert (obj);
	nm_assert (klass);

	*obj = (NMPObject) {
		.parent = {
			.klass      = (const NMDedupMultiObjClass *) klass,
			._ref_count = NM_OBJ_REF_COUNT_STACKINIT,
		},
	};
}

static NMPObject *
_nmp_object_stackinit_from_type (NMPObject *obj, NMPObjectType obj_type)
{
	const NMPClass *klass;

	nm_assert (obj);
	klass = nmp_class_from_type (obj_type);
	nm_assert (klass);

	*obj = (NMPObject) {
		.parent = {
			.klass      = (const NMDedupMultiObjClass *) klass,
			._ref_count = NM_OBJ_REF_COUNT_STACKINIT,
		},
	};
	return obj;
}

const NMPObject *
nmp_object_stackinit (NMPObject *obj, NMPObjectType obj_type, gconstpointer plobj)
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
	_nmp_object_stackinit_from_class (obj, klass);
	if (klass->cmd_plobj_id_copy)
		klass->cmd_plobj_id_copy (&obj->object, &src->object);
	return obj;
}

const NMPObject *
nmp_object_stackinit_id_link (NMPObject *obj, int ifindex)
{
	_nmp_object_stackinit_from_type (obj, NMP_OBJECT_TYPE_LINK);
	obj->link.ifindex = ifindex;
	return obj;
}

const NMPObject *
nmp_object_stackinit_id_ip4_address (NMPObject *obj, int ifindex, guint32 address, guint8 plen, guint32 peer_address)
{
	_nmp_object_stackinit_from_type (obj, NMP_OBJECT_TYPE_IP4_ADDRESS);
	obj->ip4_address.ifindex = ifindex;
	obj->ip4_address.address = address;
	obj->ip4_address.plen = plen;
	obj->ip4_address.peer_address = peer_address;
	return obj;
}

const NMPObject *
nmp_object_stackinit_id_ip6_address (NMPObject *obj, int ifindex, const struct in6_addr *address)
{
	_nmp_object_stackinit_from_type (obj, NMP_OBJECT_TYPE_IP6_ADDRESS);
	obj->ip4_address.ifindex = ifindex;
	if (address)
		obj->ip6_address.address = *address;
	return obj;
}

/*****************************************************************************/

const char *
nmp_object_to_string (const NMPObject *obj, NMPObjectToStringMode to_string_mode, char *buf, gsize buf_size)
{
	const NMPClass *klass;
	char buf2[sizeof (_nm_utils_to_string_buffer)];

	if (!nm_utils_to_string_buffer_init_null (obj, &buf, &buf_size))
		return buf;

	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj), NULL);

	klass = NMP_OBJECT_GET_CLASS (obj);

	if (klass->cmd_obj_to_string)
		return klass->cmd_obj_to_string (obj, to_string_mode, buf, buf_size);

	switch (to_string_mode) {
	case NMP_OBJECT_TO_STRING_ID:
		if (!klass->cmd_plobj_to_string_id) {
			g_snprintf (buf, buf_size, "%p", obj);
			return buf;
		}
		return klass->cmd_plobj_to_string_id (&obj->object, buf, buf_size);
	case NMP_OBJECT_TO_STRING_ALL:
		g_snprintf (buf, buf_size,
		            "[%s,%p,%u,%calive,%cvisible; %s]",
		            klass->obj_type_name, obj, obj->parent._ref_count,
		            nmp_object_is_alive (obj) ? '+' : '-',
		            nmp_object_is_visible (obj) ? '+' : '-',
		            NMP_OBJECT_GET_CLASS (obj)->cmd_plobj_to_string (&obj->object, buf2, sizeof (buf2)));
		return buf;
	case NMP_OBJECT_TO_STRING_PUBLIC:
		NMP_OBJECT_GET_CLASS (obj)->cmd_plobj_to_string (&obj->object, buf, buf_size);
		return buf;
	default:
		g_return_val_if_reached ("ERROR");
	}
}

static const char *
_vt_cmd_obj_to_string_link (const NMPObject *obj, NMPObjectToStringMode to_string_mode, char *buf, gsize buf_size)
{
	const NMPClass *klass = NMP_OBJECT_GET_CLASS (obj);
	char *b = buf;

	switch (to_string_mode) {
	case NMP_OBJECT_TO_STRING_ID:
		return klass->cmd_plobj_to_string_id (&obj->object, buf, buf_size);
	case NMP_OBJECT_TO_STRING_ALL:
		nm_utils_strbuf_append (&b, &buf_size,
		                        "[%s,%p,%u,%calive,%cvisible,%cin-nl,%p; ",
		                        klass->obj_type_name, obj, obj->parent._ref_count,
		                        nmp_object_is_alive (obj) ? '+' : '-',
		                        nmp_object_is_visible (obj) ? '+' : '-',
		                        obj->_link.netlink.is_in_netlink ? '+' : '-',
		                        obj->_link.udev.device);
		NMP_OBJECT_GET_CLASS (obj)->cmd_plobj_to_string (&obj->object, b, buf_size);
		nm_utils_strbuf_seek_end (&b, &buf_size);
		if (obj->_link.netlink.lnk) {
			nm_utils_strbuf_append_str (&b, &buf_size, "; ");
			nmp_object_to_string (obj->_link.netlink.lnk, NMP_OBJECT_TO_STRING_ALL, b, buf_size);
			nm_utils_strbuf_seek_end (&b, &buf_size);
		}
		nm_utils_strbuf_append_c (&b, &buf_size, ']');
		return buf;
	case NMP_OBJECT_TO_STRING_PUBLIC:
		NMP_OBJECT_GET_CLASS (obj)->cmd_plobj_to_string (&obj->object, b, buf_size);
		if (obj->_link.netlink.lnk) {
			nm_utils_strbuf_seek_end (&b, &buf_size);
			nm_utils_strbuf_append_str (&b, &buf_size, "; ");
			nmp_object_to_string (obj->_link.netlink.lnk, NMP_OBJECT_TO_STRING_PUBLIC, b, buf_size);
		}
		return buf;
	default:
		g_return_val_if_reached ("ERROR");
	}
}

static const char *
_vt_cmd_obj_to_string_lnk_vlan (const NMPObject *obj, NMPObjectToStringMode to_string_mode, char *buf, gsize buf_size)
{
	const NMPClass *klass;
	char buf2[sizeof (_nm_utils_to_string_buffer)];
	char *b;
	gsize l;

	klass = NMP_OBJECT_GET_CLASS (obj);

	switch (to_string_mode) {
	case NMP_OBJECT_TO_STRING_ID:
		g_snprintf (buf, buf_size, "%p", obj);
		return buf;
	case NMP_OBJECT_TO_STRING_ALL:

		g_snprintf (buf, buf_size,
		            "[%s,%p,%u,%calive,%cvisible; %s]",
		            klass->obj_type_name, obj, obj->parent._ref_count,
		            nmp_object_is_alive (obj) ? '+' : '-',
		            nmp_object_is_visible (obj) ? '+' : '-',
		            nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_PUBLIC, buf2, sizeof (buf2)));
		return buf;
	case NMP_OBJECT_TO_STRING_PUBLIC:
		NMP_OBJECT_GET_CLASS (obj)->cmd_plobj_to_string (&obj->object, buf, buf_size);

		b = buf;
		l = strlen (b);
		b += l;
		buf_size -= l;

		if (obj->_lnk_vlan.n_ingress_qos_map) {
			nm_platform_vlan_qos_mapping_to_string (" ingress-qos-map",
			                                        obj->_lnk_vlan.ingress_qos_map,
			                                        obj->_lnk_vlan.n_ingress_qos_map,
			                                        b,
			                                        buf_size);
			l = strlen (b);
			b += l;
			buf_size -= l;
		}
		if (obj->_lnk_vlan.n_egress_qos_map) {
			nm_platform_vlan_qos_mapping_to_string (" egress-qos-map",
			                                        obj->_lnk_vlan.egress_qos_map,
			                                        obj->_lnk_vlan.n_egress_qos_map,
			                                        b,
			                                        buf_size);
			l = strlen (b);
			b += l;
			buf_size -= l;
		}

		return buf;
	default:
		g_return_val_if_reached ("ERROR");
	}
}

static const char *
_vt_cmd_obj_to_string_lnk_wireguard (const NMPObject *obj, NMPObjectToStringMode to_string_mode, char *buf, gsize buf_size)
{
	const NMPClass *klass;
	char buf2[sizeof (_nm_utils_to_string_buffer)];
	char *b;
	guint i;

	klass = NMP_OBJECT_GET_CLASS (obj);

	switch (to_string_mode) {
	case NMP_OBJECT_TO_STRING_ID:
		g_snprintf (buf, buf_size, "%p", obj);
		return buf;
	case NMP_OBJECT_TO_STRING_ALL:
		b = buf;

		nm_utils_strbuf_append (&b, &buf_size,
		                        "[%s,%p,%u,%calive,%cvisible; %s"
		                        "%s",
		                        klass->obj_type_name, obj, obj->parent._ref_count,
		                        nmp_object_is_alive (obj) ? '+' : '-',
		                        nmp_object_is_visible (obj) ? '+' : '-',
		                        nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_PUBLIC, buf2, sizeof (buf2)),
		                        obj->_lnk_wireguard.peers_len > 0
		                          ? " peers {"
		                          : "");

		for (i = 0; i < obj->_lnk_wireguard.peers_len; i++) {
			const NMPWireGuardPeer *peer = &obj->_lnk_wireguard.peers[i];

			nm_utils_strbuf_append_str (&b, &buf_size, " { ");
			nm_platform_wireguard_peer_to_string (peer, b, buf_size);
			nm_utils_strbuf_seek_end (&b, &buf_size);
			nm_utils_strbuf_append_str (&b, &buf_size, " }");
		}
		if (obj->_lnk_wireguard.peers_len)
			nm_utils_strbuf_append_str (&b, &buf_size, " }");

		return buf;
	case NMP_OBJECT_TO_STRING_PUBLIC:
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
	_nm_unused char buf1[NM_UTILS_INET_ADDRSTRLEN]; \
	_nm_unused char buf2[NM_UTILS_INET_ADDRSTRLEN]; \
	\
	g_snprintf (buf, buf_len, \
	            __VA_ARGS__); \
	return buf; \
}
_vt_cmd_plobj_to_string_id (link,        NMPlatformLink,       "%d",            obj->ifindex);
_vt_cmd_plobj_to_string_id (ip4_address, NMPlatformIP4Address, "%d: %s/%d%s%s", obj->ifindex, nm_utils_inet4_ntop ( obj->address, buf1), obj->plen,
                                                               obj->peer_address != obj->address ? "," : "",
                                                               obj->peer_address != obj->address ? nm_utils_inet4_ntop (nm_utils_ip4_address_clear_host_address (obj->peer_address, obj->plen), buf2) : "");
_vt_cmd_plobj_to_string_id (ip6_address, NMPlatformIP6Address, "%d: %s",        obj->ifindex, nm_utils_inet6_ntop (&obj->address, buf1));
_vt_cmd_plobj_to_string_id (qdisc,       NMPlatformQdisc,      "%d: %d",        obj->ifindex, obj->parent);
_vt_cmd_plobj_to_string_id (tfilter,     NMPlatformTfilter,    "%d: %d",        obj->ifindex, obj->parent);

void
nmp_object_hash_update (const NMPObject *obj, NMHashState *h)
{
	const NMPClass *klass;

	g_return_if_fail (NMP_OBJECT_IS_VALID (obj));

	klass = NMP_OBJECT_GET_CLASS (obj);

	nm_hash_update_val (h, klass->obj_type);
	if (klass->cmd_obj_hash_update)
		klass->cmd_obj_hash_update (obj, h);
	else if (klass->cmd_plobj_hash_update)
		klass->cmd_plobj_hash_update (&obj->object, h);
	else
		nm_hash_update_val (h, obj);
}

static void
_vt_cmd_obj_hash_update_link (const NMPObject *obj, NMHashState *h)
{
	nm_assert (NMP_OBJECT_GET_TYPE (obj) == NMP_OBJECT_TYPE_LINK);

	nm_platform_link_hash_update (&obj->link, h);
	nm_hash_update_vals (h,
	                     obj->_link.netlink.is_in_netlink,
	                     obj->_link.wireguard_family_id,
	                     obj->_link.udev.device);
	if (obj->_link.netlink.lnk)
		nmp_object_hash_update (obj->_link.netlink.lnk, h);
}

static void
_vt_cmd_obj_hash_update_lnk_vlan (const NMPObject *obj, NMHashState *h)
{
	nm_assert (NMP_OBJECT_GET_TYPE (obj) == NMP_OBJECT_TYPE_LNK_VLAN);

	nm_platform_lnk_vlan_hash_update (&obj->lnk_vlan, h);
	_vlan_xgress_qos_mappings_hash_update (obj->_lnk_vlan.n_ingress_qos_map,
	                                       obj->_lnk_vlan.ingress_qos_map,
	                                       h);
	_vlan_xgress_qos_mappings_hash_update (obj->_lnk_vlan.n_egress_qos_map,
	                                       obj->_lnk_vlan.egress_qos_map,
	                                       h);
}

static void
_vt_cmd_obj_hash_update_lnk_wireguard (const NMPObject *obj, NMHashState *h)
{
	guint i;

	nm_assert (NMP_OBJECT_GET_TYPE (obj) == NMP_OBJECT_TYPE_LNK_WIREGUARD);

	nm_platform_lnk_wireguard_hash_update (&obj->lnk_wireguard, h);

	nm_hash_update_val (h, obj->_lnk_wireguard.peers_len);
	for (i = 0; i < obj->_lnk_wireguard.peers_len; i++)
		_wireguard_peer_hash_update (&obj->_lnk_wireguard.peers[i], h);
}

int
nmp_object_cmp (const NMPObject *obj1, const NMPObject *obj2)
{
	const NMPClass *klass1, *klass2;

	NM_CMP_SELF (obj1, obj2);

	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj1), -1);
	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj2), 1);

	klass1 = NMP_OBJECT_GET_CLASS (obj1);
	klass2 = NMP_OBJECT_GET_CLASS (obj2);

	if (klass1 != klass2) {
		nm_assert (klass1->obj_type != klass2->obj_type);
		return klass1->obj_type < klass2->obj_type ? -1 : 1;
	}

	if (klass1->cmd_obj_cmp)
		return klass1->cmd_obj_cmp (obj1, obj2);
	return klass1->cmd_plobj_cmp (&obj1->object, &obj2->object);
}

static int
_vt_cmd_obj_cmp_link (const NMPObject *obj1, const NMPObject *obj2)
{
	NM_CMP_RETURN (nm_platform_link_cmp (&obj1->link, &obj2->link));
	NM_CMP_DIRECT (obj1->_link.netlink.is_in_netlink, obj2->_link.netlink.is_in_netlink);
	NM_CMP_RETURN (nmp_object_cmp (obj1->_link.netlink.lnk, obj2->_link.netlink.lnk));
	NM_CMP_DIRECT (obj1->_link.wireguard_family_id, obj2->_link.wireguard_family_id);

	if (obj1->_link.udev.device != obj2->_link.udev.device) {
		if (!obj1->_link.udev.device)
			return -1;
		if (!obj2->_link.udev.device)
			return 1;

		/* Only compare based on pointer values. That is ugly because it's not a
		 * stable sort order.
		 *
		 * Have this check as very last. */
		return (obj1->_link.udev.device < obj2->_link.udev.device) ? -1 : 1;
	}

	return 0;
}

static int
_vt_cmd_obj_cmp_lnk_vlan (const NMPObject *obj1, const NMPObject *obj2)
{
	int c;

	c = nm_platform_lnk_vlan_cmp (&obj1->lnk_vlan, &obj2->lnk_vlan);
	if (c)
		return c;

	if (obj1->_lnk_vlan.n_ingress_qos_map != obj2->_lnk_vlan.n_ingress_qos_map)
		return obj1->_lnk_vlan.n_ingress_qos_map < obj2->_lnk_vlan.n_ingress_qos_map ? -1 : 1;
	if (obj1->_lnk_vlan.n_egress_qos_map != obj2->_lnk_vlan.n_egress_qos_map)
		return obj1->_lnk_vlan.n_egress_qos_map < obj2->_lnk_vlan.n_egress_qos_map ? -1 : 1;

	c = _vlan_xgress_qos_mappings_cmp (obj1->_lnk_vlan.n_ingress_qos_map, obj1->_lnk_vlan.ingress_qos_map, obj2->_lnk_vlan.ingress_qos_map);
	if (c)
		return c;
	c = _vlan_xgress_qos_mappings_cmp (obj1->_lnk_vlan.n_egress_qos_map, obj1->_lnk_vlan.egress_qos_map, obj2->_lnk_vlan.egress_qos_map);

	return c;
}

static int
_vt_cmd_obj_cmp_lnk_wireguard (const NMPObject *obj1, const NMPObject *obj2)
{
	guint i;

	NM_CMP_RETURN (nm_platform_lnk_wireguard_cmp (&obj1->lnk_wireguard, &obj2->lnk_wireguard));

	NM_CMP_FIELD (obj1, obj2, _lnk_wireguard.peers_len);

	for (i = 0; i < obj1->_lnk_wireguard.peers_len; i++)
		NM_CMP_RETURN (_wireguard_peer_cmp (&obj1->_lnk_wireguard.peers[i], &obj2->_lnk_wireguard.peers[i]));

	return 0;
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
			udev_device_ref (src->_link.udev.device);
		if (dst->_link.udev.device)
			udev_device_unref (dst->_link.udev.device);
		dst->_link.udev.device = src->_link.udev.device;
	}
	if (dst->_link.netlink.lnk != src->_link.netlink.lnk) {
		if (src->_link.netlink.lnk)
			nmp_object_ref (src->_link.netlink.lnk);
		if (dst->_link.netlink.lnk)
			nmp_object_unref (dst->_link.netlink.lnk);
		dst->_link.netlink.lnk = src->_link.netlink.lnk;
	}
	if (dst->_link.ext_data != src->_link.ext_data) {
		if (dst->_link.ext_data)
			g_clear_object (&dst->_link.ext_data);
		if (src->_link.ext_data)
			dst->_link.ext_data = g_object_ref (src->_link.ext_data);
	}
	dst->_link = src->_link;
}

static void
_vt_cmd_obj_copy_lnk_vlan (NMPObject *dst, const NMPObject *src)
{
	dst->lnk_vlan = src->lnk_vlan;
	_vlan_xgress_qos_mappings_cpy (&dst->_lnk_vlan.n_ingress_qos_map,
	                               NM_UNCONST_PPTR (NMVlanQosMapping, &dst->_lnk_vlan.ingress_qos_map),
	                               src->_lnk_vlan.n_ingress_qos_map,
	                               src->_lnk_vlan.ingress_qos_map);
	_vlan_xgress_qos_mappings_cpy (&dst->_lnk_vlan.n_egress_qos_map,
	                               NM_UNCONST_PPTR (NMVlanQosMapping, &dst->_lnk_vlan.egress_qos_map),
	                               src->_lnk_vlan.n_egress_qos_map,
	                               src->_lnk_vlan.egress_qos_map);
}

static void
_vt_cmd_obj_copy_lnk_wireguard (NMPObject *dst, const NMPObject *src)
{
	guint i;

	nm_assert (dst != src);

	_wireguard_clear (&dst->_lnk_wireguard);

	dst->_lnk_wireguard = src->_lnk_wireguard;

	dst->_lnk_wireguard.peers = nm_memdup (dst->_lnk_wireguard.peers,
	                                       sizeof (NMPWireGuardPeer) * dst->_lnk_wireguard.peers_len);
	dst->_lnk_wireguard._allowed_ips_buf = nm_memdup (dst->_lnk_wireguard._allowed_ips_buf,
	                                                  sizeof (NMPWireGuardAllowedIP) * dst->_lnk_wireguard._allowed_ips_buf_len);

	/* all the peers' pointers point into the buffer. They need to be readjusted. */
	for (i = 0; i < dst->_lnk_wireguard.peers_len; i++) {
		NMPWireGuardPeer *peer = (NMPWireGuardPeer *) &dst->_lnk_wireguard.peers[i];

		if (peer->allowed_ips_len == 0) {
			nm_assert (!peer->allowed_ips);
			continue;
		}
		nm_assert (dst->_lnk_wireguard._allowed_ips_buf_len > 0);
		nm_assert (src->_lnk_wireguard._allowed_ips_buf);
		nm_assert (peer->allowed_ips >= src->_lnk_wireguard._allowed_ips_buf);
		nm_assert (&peer->allowed_ips[peer->allowed_ips_len] <= &src->_lnk_wireguard._allowed_ips_buf[src->_lnk_wireguard._allowed_ips_buf_len]);

		peer->allowed_ips = &dst->_lnk_wireguard._allowed_ips_buf[peer->allowed_ips - src->_lnk_wireguard._allowed_ips_buf];
	}

	nm_assert (nmp_object_equal (src, dst));
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
	*dst = *src;
	nm_assert (nm_platform_ip4_route_cmp (dst, src, NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID) == 0);
});
_vt_cmd_plobj_id_copy (ip6_route, NMPlatformIP6Route, {
	*dst = *src;
	nm_assert (nm_platform_ip6_route_cmp (dst, src, NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID) == 0);
});
_vt_cmd_plobj_id_copy (routing_rule, NMPlatformRoutingRule, {
	*dst = *src;
	nm_assert (nm_platform_routing_rule_cmp (dst, src, NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID) == 0);
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

int
nmp_object_id_cmp (const NMPObject *obj1, const NMPObject *obj2)
{
	const NMPClass *klass, *klass2;

	NM_CMP_SELF (obj1, obj2);

	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj1), FALSE);
	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj2), FALSE);

	klass = NMP_OBJECT_GET_CLASS (obj1);
	nm_assert (!klass->cmd_plobj_id_hash_update == !klass->cmd_plobj_id_cmp);

	klass2 = NMP_OBJECT_GET_CLASS (obj2);
	nm_assert (klass);
	if (klass != klass2) {
		nm_assert (klass2);
		NM_CMP_DIRECT (klass->obj_type, klass2->obj_type);
		/* resort to pointer comparison */
		if (klass < klass2)
			return -1;
		return 1;
	}

	if (!klass->cmd_plobj_id_cmp) {
		/* the klass doesn't implement ID cmp(). That means, different objects
		 * never compare equal, but the cmp() according to their pointer value. */
		return (obj1 < obj2) ? -1 : 1;
	}

	return klass->cmd_plobj_id_cmp (&obj1->object, &obj2->object);
}

#define _vt_cmd_plobj_id_cmp(type, plat_type, cmd) \
static int \
_vt_cmd_plobj_id_cmp_##type (const NMPlatformObject *_obj1, const NMPlatformObject *_obj2) \
{ \
	const plat_type *const obj1 = (const plat_type *) _obj1; \
	const plat_type *const obj2 = (const plat_type *) _obj2; \
	\
	NM_CMP_SELF (obj1, obj2); \
	{ cmd; } \
	return 0; \
}
_vt_cmd_plobj_id_cmp (link, NMPlatformLink,
                      NM_CMP_FIELD (obj1, obj2, ifindex);
)
_vt_cmd_plobj_id_cmp (ip4_address, NMPlatformIP4Address,
                      NM_CMP_FIELD (obj1, obj2, ifindex);
                      NM_CMP_FIELD (obj1, obj2, plen);
                      NM_CMP_FIELD (obj1, obj2, address);
                      /* for IPv4 addresses, you can add the same local address with differing peer-adddress
                       * (IFA_ADDRESS), provided that their net-part differs. */
                      NM_CMP_DIRECT_IN4ADDR_SAME_PREFIX (obj1->peer_address, obj2->peer_address, obj1->plen);
)
_vt_cmd_plobj_id_cmp (ip6_address, NMPlatformIP6Address,
                      NM_CMP_FIELD (obj1, obj2, ifindex);
                      /* for IPv6 addresses, the prefix length is not part of the primary identifier. */
                      NM_CMP_FIELD_IN6ADDR (obj1, obj2, address);
)
_vt_cmd_plobj_id_cmp (qdisc, NMPlatformQdisc,
                      NM_CMP_FIELD (obj1, obj2, ifindex);
                      NM_CMP_FIELD (obj1, obj2, parent);
)
_vt_cmd_plobj_id_cmp (tfilter, NMPlatformTfilter,
                      NM_CMP_FIELD (obj1, obj2, ifindex);
                      NM_CMP_FIELD (obj1, obj2, handle);
)

static int
_vt_cmd_plobj_id_cmp_ip4_route (const NMPlatformObject *obj1, const NMPlatformObject *obj2)
{
	return nm_platform_ip4_route_cmp ((NMPlatformIP4Route *) obj1, (NMPlatformIP4Route *) obj2, NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID);
}

static int
_vt_cmd_plobj_id_cmp_ip6_route (const NMPlatformObject *obj1, const NMPlatformObject *obj2)
{
	return nm_platform_ip6_route_cmp ((NMPlatformIP6Route *) obj1, (NMPlatformIP6Route *) obj2, NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID);
}

static int
_vt_cmd_plobj_id_cmp_routing_rule (const NMPlatformObject *obj1, const NMPlatformObject *obj2)
{
	return nm_platform_routing_rule_cmp ((NMPlatformRoutingRule *) obj1, (NMPlatformRoutingRule *) obj2, NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID);
}

void
nmp_object_id_hash_update (const NMPObject *obj, NMHashState *h)
{
	const NMPClass *klass;

	g_return_if_fail (NMP_OBJECT_IS_VALID (obj));

	klass = NMP_OBJECT_GET_CLASS (obj);

	nm_assert (!klass->cmd_plobj_id_hash_update == !klass->cmd_plobj_id_cmp);

	if (!klass->cmd_plobj_id_hash_update) {
		/* The klass doesn't implement ID compare. It means, to use pointer
		 * equality. */
		nm_hash_update_val (h, obj);
		return;
	}

	nm_hash_update_val (h, klass->obj_type);
	klass->cmd_plobj_id_hash_update (&obj->object, h);
}

guint
nmp_object_id_hash (const NMPObject *obj)
{
	NMHashState h;

	if (!obj)
		return nm_hash_static (914932607u);

	nm_hash_init (&h, 914932607u);
	nmp_object_id_hash_update (obj, &h);
	return nm_hash_complete (&h);
}

#define _vt_cmd_plobj_id_hash_update(type, plat_type, cmd) \
static void \
_vt_cmd_plobj_id_hash_update_##type (const NMPlatformObject *_obj, NMHashState *h) \
{ \
	const plat_type *const obj = (const plat_type *) _obj; \
	{ cmd; } \
}
_vt_cmd_plobj_id_hash_update (link, NMPlatformLink, {
	nm_hash_update_val (h, obj->ifindex);
})
_vt_cmd_plobj_id_hash_update (ip4_address, NMPlatformIP4Address, {
	nm_hash_update_vals (h,
	                     obj->ifindex,
	                     obj->plen,
	                     obj->address,
	                     /* for IPv4 we must also consider the net-part of the peer-address (IFA_ADDRESS) */
	                     nm_utils_ip4_address_clear_host_address (obj->peer_address, obj->plen));
})
_vt_cmd_plobj_id_hash_update (ip6_address, NMPlatformIP6Address, {
	nm_hash_update_vals (h,
	                     obj->ifindex,
	                     /* for IPv6 addresses, the prefix length is not part of the primary identifier. */
	                     obj->address);
})
_vt_cmd_plobj_id_hash_update (ip4_route, NMPlatformIP4Route, {
	nm_platform_ip4_route_hash_update (obj, NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID, h);
})
_vt_cmd_plobj_id_hash_update (ip6_route, NMPlatformIP6Route, {
	nm_platform_ip6_route_hash_update (obj, NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID, h);
})
_vt_cmd_plobj_id_hash_update (routing_rule, NMPlatformRoutingRule, {
	nm_platform_routing_rule_hash_update (obj, NM_PLATFORM_ROUTING_RULE_CMP_TYPE_ID, h);
})
_vt_cmd_plobj_id_hash_update (qdisc, NMPlatformQdisc, {
	nm_hash_update_vals (h,
	                     obj->ifindex,
	                     obj->parent);
})
_vt_cmd_plobj_id_hash_update (tfilter, NMPlatformTfilter, {
	nm_hash_update_vals (h,
	                     obj->ifindex,
	                     obj->handle);
})

static void
_vt_cmd_plobj_hash_update_ip4_route (const NMPlatformObject *obj, NMHashState *h)
{
	return nm_platform_ip4_route_hash_update ((const NMPlatformIP4Route *) obj, NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL, h);
}

static void
_vt_cmd_plobj_hash_update_ip6_route (const NMPlatformObject *obj, NMHashState *h)
{
	return nm_platform_ip6_route_hash_update ((const NMPlatformIP6Route *) obj, NM_PLATFORM_IP_ROUTE_CMP_TYPE_FULL, h);
}

static void
_vt_cmd_plobj_hash_update_routing_rule (const NMPlatformObject *obj, NMHashState *h)
{
	return nm_platform_routing_rule_hash_update ((const NMPlatformRoutingRule *) obj, NM_PLATFORM_ROUTING_RULE_CMP_TYPE_FULL, h);
}

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
	return    NMP_OBJECT_CAST_LINK (obj)->ifindex > 0
	       && (obj->_link.netlink.is_in_netlink || obj->_link.udev.device);
}

static gboolean
_vt_cmd_obj_is_alive_ipx_address (const NMPObject *obj)
{
	return NMP_OBJECT_CAST_IP_ADDRESS (obj)->ifindex > 0;
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
	 * (because it changed to be cloned).
	 *
	 * Instead we create a dead object, and nmp_cache_update_netlink()
	 * will remove the old version of the update.
	 **/
	return    NMP_OBJECT_CAST_IP_ROUTE (obj)->ifindex > 0
	       && !NM_FLAGS_HAS (obj->ip_route.r_rtm_flags, RTM_F_CLONED);
}

static gboolean
_vt_cmd_obj_is_alive_routing_rule (const NMPObject *obj)
{
	return NM_IN_SET (obj->routing_rule.addr_family, AF_INET, AF_INET6);
}

static gboolean
_vt_cmd_obj_is_alive_qdisc (const NMPObject *obj)
{
	return NMP_OBJECT_CAST_QDISC (obj)->ifindex > 0;
}

static gboolean
_vt_cmd_obj_is_alive_tfilter (const NMPObject *obj)
{
	return NMP_OBJECT_CAST_TFILTER (obj)->ifindex > 0;
}

gboolean
nmp_object_is_visible (const NMPObject *obj)
{
	const NMPClass *klass;

	/* for convenience, allow NULL. */
	if (!obj)
		return FALSE;

	klass = NMP_OBJECT_GET_CLASS (obj);

	/* a dead object is never visible. */
	if (   klass->cmd_obj_is_alive
	    && !klass->cmd_obj_is_alive (obj))
		return FALSE;

	return    !klass->cmd_obj_is_visible
	       || klass->cmd_obj_is_visible (obj);
}

static gboolean
_vt_cmd_obj_is_visible_link (const NMPObject *obj)
{
	return    obj->_link.netlink.is_in_netlink
	       && obj->link.name[0];
}

/*****************************************************************************/

static const guint8 _supported_cache_ids_object[] = {
	NMP_CACHE_ID_TYPE_OBJECT_TYPE,
	NMP_CACHE_ID_TYPE_OBJECT_BY_IFINDEX,
	0,
};

static const guint8 _supported_cache_ids_link[] = {
	NMP_CACHE_ID_TYPE_OBJECT_TYPE,
	NMP_CACHE_ID_TYPE_LINK_BY_IFNAME,
	0,
};

static const guint8 _supported_cache_ids_ipx_address[] = {
	NMP_CACHE_ID_TYPE_OBJECT_TYPE,
	NMP_CACHE_ID_TYPE_OBJECT_BY_IFINDEX,
	0,
};

static const guint8 _supported_cache_ids_ipx_route[] = {
	NMP_CACHE_ID_TYPE_OBJECT_TYPE,
	NMP_CACHE_ID_TYPE_OBJECT_BY_IFINDEX,
	NMP_CACHE_ID_TYPE_DEFAULT_ROUTES,
	NMP_CACHE_ID_TYPE_ROUTES_BY_WEAK_ID,
	0,
};

static const guint8 _supported_cache_ids_routing_rules[] = {
	NMP_CACHE_ID_TYPE_OBJECT_TYPE,
	NMP_CACHE_ID_TYPE_OBJECT_BY_ADDR_FAMILY,
	0,
};

/*****************************************************************************/

static void
_vt_dedup_obj_destroy (NMDedupMultiObj *obj)
{
	NMPObject *o = (NMPObject *) obj;
	const NMPClass *klass;

	nm_assert (o->parent._ref_count == 0);
	nm_assert (!o->parent._multi_idx);

	klass = o->_class;
	if (klass->cmd_obj_dispose)
		klass->cmd_obj_dispose (o);
	g_slice_free1 (klass->sizeof_data + G_STRUCT_OFFSET (NMPObject, object), o);
}

static const NMDedupMultiObj *
_vt_dedup_obj_clone (const NMDedupMultiObj *obj)
{
	return (const NMDedupMultiObj *) nmp_object_clone ((const NMPObject *) obj, FALSE);
}

#define DEDUP_MULTI_OBJ_CLASS_INIT() \
	{ \
		.obj_clone                      = _vt_dedup_obj_clone, \
		.obj_destroy                    = _vt_dedup_obj_destroy, \
		.obj_full_hash_update           = (void (*)(const NMDedupMultiObj *obj, NMHashState *h)) nmp_object_hash_update, \
		.obj_full_equal                 = (gboolean (*)(const NMDedupMultiObj *obj_a, const NMDedupMultiObj *obj_b)) nmp_object_equal, \
	}

/*****************************************************************************/

static NMDedupMultiIdxType *
_idx_type_get (const NMPCache *cache, NMPCacheIdType cache_id_type)
{
	nm_assert (cache);
	nm_assert (cache_id_type > NMP_CACHE_ID_TYPE_NONE);
	nm_assert (cache_id_type <= NMP_CACHE_ID_TYPE_MAX);
	nm_assert ((int) cache_id_type - 1 >= 0);
	nm_assert ((int) cache_id_type - 1 < G_N_ELEMENTS (cache->idx_types));

	return (NMDedupMultiIdxType *) &cache->idx_types[cache_id_type - 1];
}

gboolean
nmp_cache_use_udev_get (const NMPCache *cache)
{
	g_return_val_if_fail (cache, TRUE);

	return cache->use_udev;
}

/*****************************************************************************/

gboolean
nmp_cache_link_connected_for_slave (int ifindex_master, const NMPObject *slave)
{
	nm_assert (NMP_OBJECT_GET_TYPE (slave) == NMP_OBJECT_TYPE_LINK);

	return    ifindex_master > 0
	       && slave->link.master == ifindex_master
	       && slave->link.connected
	       && nmp_object_is_visible (slave);
}

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
	gboolean is_lower_up = FALSE;

	if (   !master
	    || NMP_OBJECT_GET_TYPE (master) != NMP_OBJECT_TYPE_LINK
	    || master->link.ifindex <= 0
	    || !nmp_object_is_visible (master)
	    || !NM_IN_SET (master->link.type, NM_LINK_TYPE_BRIDGE, NM_LINK_TYPE_BOND))
		return FALSE;

	/* if native IFF_LOWER_UP is down, link.connected must also be down
	 * regardless of the slaves. */
	if (!NM_FLAGS_HAS (master->link.n_ifi_flags, IFF_LOWER_UP))
		return !!master->link.connected;

	if (potential_slave && NMP_OBJECT_GET_TYPE (potential_slave) != NMP_OBJECT_TYPE_LINK)
		potential_slave = NULL;

	if (   potential_slave
	    && nmp_cache_link_connected_for_slave (master->link.ifindex, potential_slave))
		is_lower_up = TRUE;
	else {
		NMPLookup lookup;
		NMDedupMultiIter iter;
		const NMPlatformLink *link = NULL;

		nmp_cache_iter_for_each_link (&iter,
		                              nmp_cache_lookup (cache,
		                                                nmp_lookup_init_obj_type (&lookup,
		                                                                          NMP_OBJECT_TYPE_LINK)),
		                              &link) {
			const NMPObject *obj = NMP_OBJECT_UP_CAST ((NMPlatformObject *) link);

			if (   (!potential_slave || potential_slave->link.ifindex != link->ifindex)
			    && ignore_slave != obj
			    && nmp_cache_link_connected_for_slave (master->link.ifindex, obj)) {
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
 * toggling of the connected flag.
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

/*****************************************************************************/

static const NMDedupMultiEntry *
_lookup_entry_with_idx_type (const NMPCache *cache,
                             NMPCacheIdType cache_id_type,
                             const NMPObject *obj)
{
	const NMDedupMultiEntry *entry;

	nm_assert (cache);
	nm_assert (NMP_OBJECT_IS_VALID (obj));

	entry = nm_dedup_multi_index_lookup_obj (cache->multi_idx,
	                                         _idx_type_get (cache, cache_id_type),
	                                         obj);
	nm_assert (!entry
	           || (   NMP_OBJECT_IS_VALID (entry->obj)
	               && NMP_OBJECT_GET_CLASS (entry->obj) == NMP_OBJECT_GET_CLASS (obj)));
	return entry;
}

static const NMDedupMultiEntry *
_lookup_entry (const NMPCache *cache, const NMPObject *obj)
{
	return _lookup_entry_with_idx_type (cache, NMP_CACHE_ID_TYPE_OBJECT_TYPE, obj);
}

const NMDedupMultiEntry *
nmp_cache_lookup_entry_with_idx_type (const NMPCache *cache,
                                      NMPCacheIdType cache_id_type,
                                      const NMPObject *obj)
{
	g_return_val_if_fail (cache, NULL);
	g_return_val_if_fail (obj, NULL);
	g_return_val_if_fail (cache_id_type > NMP_CACHE_ID_TYPE_NONE && cache_id_type <= NMP_CACHE_ID_TYPE_MAX, NULL);

	return _lookup_entry_with_idx_type (cache, cache_id_type, obj);
}

const NMDedupMultiEntry *
nmp_cache_lookup_entry (const NMPCache *cache, const NMPObject *obj)
{
	g_return_val_if_fail (cache, NULL);
	g_return_val_if_fail (obj, NULL);

	return _lookup_entry (cache, obj);
}

const NMDedupMultiEntry *
nmp_cache_lookup_entry_link (const NMPCache *cache, int ifindex)
{
	NMPObject obj_needle;

	g_return_val_if_fail (cache, NULL);
	g_return_val_if_fail (ifindex > 0, NULL);

	nmp_object_stackinit_id_link (&obj_needle, ifindex);
	return _lookup_entry (cache, &obj_needle);
}

const NMPObject *
nmp_cache_lookup_obj (const NMPCache *cache, const NMPObject *obj)
{
	return nm_dedup_multi_entry_get_obj (nmp_cache_lookup_entry (cache, obj));
}

const NMPObject *
nmp_cache_lookup_link (const NMPCache *cache, int ifindex)
{
	return nm_dedup_multi_entry_get_obj (nmp_cache_lookup_entry_link (cache, ifindex));
}

/*****************************************************************************/

const NMDedupMultiHeadEntry *
nmp_cache_lookup_all (const NMPCache *cache,
                      NMPCacheIdType cache_id_type,
                      const NMPObject *select_obj)
{
	nm_assert (cache);
	nm_assert (NMP_OBJECT_IS_VALID (select_obj));

	return nm_dedup_multi_index_lookup_head (cache->multi_idx,
	                                         _idx_type_get (cache, cache_id_type),
	                                         select_obj);
}

static const NMPLookup *
_L (const NMPLookup *lookup)
{
#if NM_MORE_ASSERTS
	DedupMultiIdxType idx_type;

	nm_assert (lookup);
	_dedup_multi_idx_type_init (&idx_type, lookup->cache_id_type);
	nm_assert (idx_type.parent.klass->idx_obj_partitionable  ((NMDedupMultiIdxType *) &idx_type, (NMDedupMultiObj *) &lookup->selector_obj));
#endif
	return lookup;
}

const NMPLookup *
nmp_lookup_init_obj_type (NMPLookup *lookup,
                          NMPObjectType obj_type)
{
	nm_assert (lookup);

	switch (obj_type) {
	case NMP_OBJECT_TYPE_LINK:
	case NMP_OBJECT_TYPE_IP4_ADDRESS:
	case NMP_OBJECT_TYPE_IP6_ADDRESS:
	case NMP_OBJECT_TYPE_IP4_ROUTE:
	case NMP_OBJECT_TYPE_IP6_ROUTE:
	case NMP_OBJECT_TYPE_ROUTING_RULE:
	case NMP_OBJECT_TYPE_QDISC:
	case NMP_OBJECT_TYPE_TFILTER:
		_nmp_object_stackinit_from_type (&lookup->selector_obj, obj_type);
		lookup->cache_id_type = NMP_CACHE_ID_TYPE_OBJECT_TYPE;
		return _L (lookup);
	default:
		nm_assert_not_reached ();
		return NULL;
	}
}

const NMPLookup *
nmp_lookup_init_link_by_ifname (NMPLookup *lookup,
                                const char *ifname)
{
	NMPObject *o;

	nm_assert (lookup);
	nm_assert (ifname);
	nm_assert (strlen (ifname) < IFNAMSIZ);

	o = _nmp_object_stackinit_from_type (&lookup->selector_obj, NMP_OBJECT_TYPE_LINK);
	if (g_strlcpy (o->link.name, ifname, sizeof (o->link.name)) >= sizeof (o->link.name))
		g_return_val_if_reached (NULL);
	lookup->cache_id_type = NMP_CACHE_ID_TYPE_LINK_BY_IFNAME;
	return _L (lookup);
}

const NMPLookup *
nmp_lookup_init_object (NMPLookup *lookup,
                        NMPObjectType obj_type,
                        int ifindex)
{
	NMPObject *o;

	nm_assert (lookup);
	nm_assert (NM_IN_SET (obj_type, NMP_OBJECT_TYPE_IP4_ADDRESS,
	                                NMP_OBJECT_TYPE_IP6_ADDRESS,
	                                NMP_OBJECT_TYPE_IP4_ROUTE,
	                                NMP_OBJECT_TYPE_IP6_ROUTE,
	                                NMP_OBJECT_TYPE_QDISC,
	                                NMP_OBJECT_TYPE_TFILTER));

	if (ifindex <= 0) {
		return nmp_lookup_init_obj_type (lookup,
		                                 obj_type);
	}

	o = _nmp_object_stackinit_from_type (&lookup->selector_obj, obj_type);
	o->obj_with_ifindex.ifindex = ifindex;
	lookup->cache_id_type = NMP_CACHE_ID_TYPE_OBJECT_BY_IFINDEX;
	return _L (lookup);
}

const NMPLookup *
nmp_lookup_init_route_default (NMPLookup *lookup,
                               NMPObjectType obj_type)
{
	NMPObject *o;

	nm_assert (lookup);
	nm_assert (NM_IN_SET (obj_type, NMP_OBJECT_TYPE_IP4_ROUTE,
	                                NMP_OBJECT_TYPE_IP6_ROUTE));

	o = _nmp_object_stackinit_from_type (&lookup->selector_obj, obj_type);
	o->ip_route.ifindex = 1;
	lookup->cache_id_type = NMP_CACHE_ID_TYPE_DEFAULT_ROUTES;
	return _L (lookup);
}

const NMPLookup *
nmp_lookup_init_route_by_weak_id (NMPLookup *lookup,
                                  const NMPObject *obj)
{
	const NMPlatformIP4Route *r4;
	const NMPlatformIP6Route *r6;

	nm_assert (lookup);

	switch (NMP_OBJECT_GET_TYPE (obj)) {
	case NMP_OBJECT_TYPE_IP4_ROUTE:
		r4 = NMP_OBJECT_CAST_IP4_ROUTE (obj);
		return nmp_lookup_init_ip4_route_by_weak_id (lookup,
		                                             r4->network,
		                                             r4->plen,
		                                             r4->metric,
		                                             r4->tos);
	case NMP_OBJECT_TYPE_IP6_ROUTE:
		r6 = NMP_OBJECT_CAST_IP6_ROUTE (obj);
		return nmp_lookup_init_ip6_route_by_weak_id (lookup,
		                                             &r6->network,
		                                             r6->plen,
		                                             r6->metric,
		                                             &r6->src,
		                                             r6->src_plen);
	default:
		nm_assert_not_reached ();
		return NULL;
	}
}

const NMPLookup *
nmp_lookup_init_ip4_route_by_weak_id (NMPLookup *lookup,
                                      in_addr_t network,
                                      guint plen,
                                      guint32 metric,
                                      guint8 tos)
{
	NMPObject *o;

	nm_assert (lookup);

	o = _nmp_object_stackinit_from_type (&lookup->selector_obj, NMP_OBJECT_TYPE_IP4_ROUTE);
	o->ip4_route.ifindex = 1;
	o->ip4_route.plen = plen;
	o->ip4_route.metric = metric;
	if (network)
		o->ip4_route.network = network;
	o->ip4_route.tos = tos;
	lookup->cache_id_type = NMP_CACHE_ID_TYPE_ROUTES_BY_WEAK_ID;
	return _L (lookup);
}

const NMPLookup *
nmp_lookup_init_ip6_route_by_weak_id (NMPLookup *lookup,
                                      const struct in6_addr *network,
                                      guint plen,
                                      guint32 metric,
                                      const struct in6_addr *src,
                                      guint8 src_plen)
{
	NMPObject *o;

	nm_assert (lookup);

	o = _nmp_object_stackinit_from_type (&lookup->selector_obj, NMP_OBJECT_TYPE_IP6_ROUTE);
	o->ip6_route.ifindex = 1;
	o->ip6_route.plen = plen;
	o->ip6_route.metric = metric;
	if (network)
		o->ip6_route.network = *network;
	if (src)
		o->ip6_route.src = *src;
	o->ip6_route.src_plen = src_plen;
	lookup->cache_id_type = NMP_CACHE_ID_TYPE_ROUTES_BY_WEAK_ID;
	return _L (lookup);
}

const NMPLookup *
nmp_lookup_init_object_by_addr_family (NMPLookup *lookup,
                                       NMPObjectType obj_type,
                                       int addr_family)
{
	NMPObject *o;

	nm_assert (lookup);
	nm_assert (NM_IN_SET (obj_type, NMP_OBJECT_TYPE_ROUTING_RULE));

	if (addr_family == AF_UNSPEC)
		return nmp_lookup_init_obj_type (lookup, obj_type);

	nm_assert_addr_family (addr_family);
	o = _nmp_object_stackinit_from_type (&lookup->selector_obj, obj_type);
	NMP_OBJECT_CAST_ROUTING_RULE (o)->addr_family = addr_family;
	lookup->cache_id_type = NMP_CACHE_ID_TYPE_OBJECT_BY_ADDR_FAMILY;
	return _L (lookup);
}

/*****************************************************************************/

GArray *
nmp_cache_lookup_to_array (const NMDedupMultiHeadEntry *head_entry,
                           NMPObjectType obj_type,
                           gboolean visible_only)
{
	const NMPClass *klass = nmp_class_from_type (obj_type);
	NMDedupMultiIter iter;
	const NMPObject *o;
	GArray *array;

	g_return_val_if_fail (klass, NULL);

	array = g_array_sized_new (FALSE, FALSE,
	                           klass->sizeof_public,
	                           head_entry ? head_entry->len : 0);
	nmp_cache_iter_for_each (&iter,
	                         head_entry,
	                         &o) {
		nm_assert (NMP_OBJECT_GET_CLASS (o) == klass);
		if (   visible_only
		    && !nmp_object_is_visible (o))
			continue;
		g_array_append_vals (array, &o->object, 1);
	}
	return array;
}

/*****************************************************************************/

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
	NMDedupMultiIter iter;
	const NMDedupMultiHeadEntry *head_entry;
	const NMPlatformLink *link = NULL;
	NMPLookup lookup;

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
		const NMPObject *obj_best = NULL;

		if (ifname) {
			if (strlen (ifname) >= IFNAMSIZ)
				return NULL;
			nmp_lookup_init_link_by_ifname (&lookup, ifname);
		} else
			nmp_lookup_init_obj_type (&lookup, NMP_OBJECT_TYPE_LINK);

		head_entry = nmp_cache_lookup (cache, &lookup);
		nmp_cache_iter_for_each_link (&iter, head_entry, &link) {
			obj = NMP_OBJECT_UP_CAST (link);

			if (link_type != NM_LINK_TYPE_NONE && obj->link.type != link_type)
				continue;
			if (visible_only && !nmp_object_is_visible (obj))
				continue;
			if (match_fn && !match_fn (obj, user_data))
				continue;

			/* if there are multiple candidates, prefer the visible ones. */
			if (   visible_only
			    || nmp_object_is_visible (obj))
				return obj;
			if (!obj_best)
				obj_best = obj;
		}
		return obj_best;
	}
}

/*****************************************************************************/

static NMDedupMultiIdxMode
_obj_get_add_mode (const NMPObject *obj)
{
	/* new objects are usually appended to the list. Except for
	 * addresses, which are prepended during `ip address add`.
	 *
	 * Actually, for routes it is more complicated, because depending on
	 * `ip route append`, `ip route replace`, `ip route prepend`, the object
	 * will be added at the tail, at the front, or even replace an element
	 * in the list. However, that is handled separately by nmp_cache_update_netlink_route()
	 * and of no concern here. */
	if (NM_IN_SET (NMP_OBJECT_GET_TYPE (obj),
	               NMP_OBJECT_TYPE_IP4_ADDRESS,
	               NMP_OBJECT_TYPE_IP6_ADDRESS))
		return NM_DEDUP_MULTI_IDX_MODE_PREPEND;
	return NM_DEDUP_MULTI_IDX_MODE_APPEND;
}

static void
_idxcache_update_order_for_dump (NMPCache *cache,
                                 const NMDedupMultiEntry *entry)
{
	const NMPClass *klass;
	const guint8 *i_idx_type;
	const NMDedupMultiEntry *entry2;

	nm_dedup_multi_entry_reorder (entry, NULL, TRUE);

	klass = NMP_OBJECT_GET_CLASS (entry->obj);
	for (i_idx_type = klass->supported_cache_ids; *i_idx_type; i_idx_type++) {
		NMPCacheIdType id_type = *i_idx_type;

		if (id_type == NMP_CACHE_ID_TYPE_OBJECT_TYPE)
			continue;

		entry2 = nm_dedup_multi_index_lookup_obj (cache->multi_idx,
		                                          _idx_type_get (cache, id_type),
		                                          entry->obj);
		if (!entry2)
			continue;

		nm_assert (entry2 != entry);
		nm_assert (entry2->obj == entry->obj);

		nm_dedup_multi_entry_reorder (entry2, NULL, TRUE);
	}
}

static void
_idxcache_update_other_cache_ids (NMPCache *cache,
                                  NMPCacheIdType cache_id_type,
                                  const NMPObject *obj_old,
                                  const NMPObject *obj_new,
                                  gboolean is_dump)
{
	const NMDedupMultiEntry *entry_new;
	const NMDedupMultiEntry *entry_old;
	const NMDedupMultiEntry *entry_order;
	NMDedupMultiIdxType *idx_type;

	nm_assert (obj_new || obj_old);
	nm_assert (!obj_new || NMP_OBJECT_GET_TYPE (obj_new) != NMP_OBJECT_TYPE_UNKNOWN);
	nm_assert (!obj_old || NMP_OBJECT_GET_TYPE (obj_old) != NMP_OBJECT_TYPE_UNKNOWN);
	nm_assert (!obj_old || !obj_new || NMP_OBJECT_GET_CLASS (obj_new) == NMP_OBJECT_GET_CLASS (obj_old));
	nm_assert (!obj_old || !obj_new || !nmp_object_equal (obj_new, obj_old));
	nm_assert (!obj_new || obj_new == nm_dedup_multi_index_obj_find (cache->multi_idx, obj_new));
	nm_assert (!obj_old || obj_old == nm_dedup_multi_index_obj_find (cache->multi_idx, obj_old));

	idx_type = _idx_type_get (cache, cache_id_type);

	if (obj_old) {
		entry_old = nm_dedup_multi_index_lookup_obj (cache->multi_idx,
		                                             idx_type,
		                                             obj_old);
		if (!obj_new) {
			if (entry_old)
				nm_dedup_multi_index_remove_entry (cache->multi_idx, entry_old);
			return;
		}
	} else
		entry_old = NULL;

	if (obj_new) {
		if (   obj_old
		    && nm_dedup_multi_idx_type_id_equal (idx_type, obj_old, obj_new)
		    && nm_dedup_multi_idx_type_partition_equal (idx_type, obj_old, obj_new)) {
			/* optimize. We just looked up the @obj_old entry and @obj_new compares equal
			 * according to idx_obj_id_equal(). entry_new is the same as entry_old. */
			entry_new = entry_old;
		} else {
			entry_new = nm_dedup_multi_index_lookup_obj (cache->multi_idx,
			                                             idx_type,
			                                             obj_new);
		}

		if (entry_new)
			entry_order = entry_new;
		else if (   entry_old
		         && nm_dedup_multi_idx_type_partition_equal (idx_type, entry_old->obj, obj_new))
			entry_order = entry_old;
		else
			entry_order = NULL;
		nm_dedup_multi_index_add_full (cache->multi_idx,
		                               idx_type,
		                               obj_new,
		                               is_dump
		                                 ? NM_DEDUP_MULTI_IDX_MODE_APPEND_FORCE
		                                 : _obj_get_add_mode (obj_new),
		                               is_dump
		                                 ? NULL
		                                 : entry_order,
		                               entry_new ?: NM_DEDUP_MULTI_ENTRY_MISSING,
		                               entry_new ? entry_new->head : (entry_order ? entry_order->head : NULL),
		                               &entry_new,
		                               NULL);

#if NM_MORE_ASSERTS
		if (entry_new) {
			nm_assert (idx_type->klass->idx_obj_partitionable);
			nm_assert (idx_type->klass->idx_obj_partition_equal);
			nm_assert (idx_type->klass->idx_obj_partitionable (idx_type, entry_new->obj));
			nm_assert (idx_type->klass->idx_obj_partition_equal (idx_type, (gpointer) obj_new, entry_new->obj));
		}
#endif
	} else
		entry_new = NULL;

	if (   entry_old
	    && entry_old != entry_new)
		nm_dedup_multi_index_remove_entry (cache->multi_idx, entry_old);
}

static void
_idxcache_update (NMPCache *cache,
                  const NMDedupMultiEntry *entry_old,
                  NMPObject *obj_new,
                  gboolean is_dump,
                  const NMDedupMultiEntry **out_entry_new)
{
	const NMPClass *klass;
	const guint8 *i_idx_type;
	NMDedupMultiIdxType *idx_type_o = _idx_type_get (cache, NMP_CACHE_ID_TYPE_OBJECT_TYPE);
	const NMDedupMultiEntry *entry_new = NULL;
	nm_auto_nmpobj const NMPObject *obj_old = NULL;

	/* we update an object in the cache.
	 *
	 * Note that @entry_old MUST be what is currently tracked in multi_idx, and it must
	 * have the same ID as @obj_new. */

	nm_assert (cache);
	nm_assert (entry_old || obj_new);
	nm_assert (!obj_new || nmp_object_is_alive (obj_new));
	nm_assert (!entry_old || entry_old == nm_dedup_multi_index_lookup_obj (cache->multi_idx, idx_type_o, entry_old->obj));
	nm_assert (!obj_new || entry_old == nm_dedup_multi_index_lookup_obj (cache->multi_idx, idx_type_o, obj_new));
	nm_assert (!entry_old || entry_old->head->idx_type == idx_type_o);
	nm_assert (   !entry_old
	           || !obj_new
	           || nm_dedup_multi_idx_type_partition_equal (idx_type_o, entry_old->obj, obj_new));
	nm_assert (   !entry_old
	           || !obj_new
	           || nm_dedup_multi_idx_type_id_equal (idx_type_o, entry_old->obj, obj_new));
	nm_assert (   !entry_old
	           || !obj_new
	           || (   obj_new->parent.klass == ((const NMPObject *) entry_old->obj)->parent.klass
	               && !obj_new->parent.klass->obj_full_equal ((NMDedupMultiObj *) obj_new, entry_old->obj)));

	/* keep a reference to the pre-existing entry */
	if (entry_old)
		obj_old = nmp_object_ref (entry_old->obj);

	/* first update the main index NMP_CACHE_ID_TYPE_OBJECT_TYPE.
	 * We already know the pre-existing @entry old, so all that
	 * nm_dedup_multi_index_add_full() effectively does, is update the
	 * obj reference.
	 *
	 * We also get the new boxed object, which we need below. */
	if (obj_new) {
		nm_auto_nmpobj NMPObject *obj_old2 = NULL;

		nm_dedup_multi_index_add_full (cache->multi_idx,
		                               idx_type_o,
		                               obj_new,
		                               is_dump
		                                 ? NM_DEDUP_MULTI_IDX_MODE_APPEND_FORCE
		                                 : _obj_get_add_mode (obj_new),
		                               NULL,
		                               entry_old ?: NM_DEDUP_MULTI_ENTRY_MISSING,
		                               NULL,
		                               &entry_new,
		                               (const NMDedupMultiObj **) &obj_old2);
		nm_assert (entry_new);
		nm_assert (obj_old == obj_old2);
		nm_assert (!entry_old || entry_old == entry_new);
	} else
		nm_dedup_multi_index_remove_entry (cache->multi_idx, entry_old);

	/* now update all other indexes. We know the previously boxed entry, and the
	 * newly boxed one. */
	klass = NMP_OBJECT_GET_CLASS (entry_new ? entry_new->obj : obj_old);
	for (i_idx_type = klass->supported_cache_ids; *i_idx_type; i_idx_type++) {
		NMPCacheIdType id_type = *i_idx_type;

		if (id_type == NMP_CACHE_ID_TYPE_OBJECT_TYPE)
			continue;
		_idxcache_update_other_cache_ids (cache, id_type,
		                                  obj_old,
		                                  entry_new ? entry_new->obj : NULL,
		                                  is_dump);
	}

	NM_SET_OUT (out_entry_new, entry_new);
}

NMPCacheOpsType
nmp_cache_remove (NMPCache *cache,
                  const NMPObject *obj_needle,
                  gboolean equals_by_ptr,
                  gboolean only_dirty,
                  const NMPObject **out_obj_old)
{
	const NMDedupMultiEntry *entry_old;
	const NMPObject *obj_old;

	entry_old = _lookup_entry (cache, obj_needle);

	if (!entry_old) {
		NM_SET_OUT (out_obj_old, NULL);
		return NMP_CACHE_OPS_UNCHANGED;
	}

	obj_old = entry_old->obj;

	NM_SET_OUT (out_obj_old, nmp_object_ref (obj_old));

	if (   equals_by_ptr
	    && obj_old != obj_needle) {
		/* We found an identical object, but we only delete it if it's the same pointer as
		 * @obj_needle. */
		return NMP_CACHE_OPS_UNCHANGED;
	}
	if (   only_dirty
	    && !entry_old->dirty) {
		/* the entry is not dirty. Skip. */
		return NMP_CACHE_OPS_UNCHANGED;
	}
	_idxcache_update (cache, entry_old, NULL, FALSE, NULL);
	return NMP_CACHE_OPS_REMOVED;
}

NMPCacheOpsType
nmp_cache_remove_netlink (NMPCache *cache,
                          const NMPObject *obj_needle,
                          const NMPObject **out_obj_old,
                          const NMPObject **out_obj_new)
{
	const NMDedupMultiEntry *entry_old;
	const NMDedupMultiEntry *entry_new = NULL;
	const NMPObject *obj_old;
	nm_auto_nmpobj NMPObject *obj_new = NULL;

	entry_old = _lookup_entry (cache, obj_needle);

	if (!entry_old) {
		NM_SET_OUT (out_obj_old, NULL);
		NM_SET_OUT (out_obj_new, NULL);
		return NMP_CACHE_OPS_UNCHANGED;
	}

	obj_old = entry_old->obj;

	if (NMP_OBJECT_GET_TYPE (obj_needle) == NMP_OBJECT_TYPE_LINK) {
		/* For nmp_cache_remove_netlink() we have an incomplete @obj_needle instance to be
		 * removed from netlink. Link objects are alive without being in netlink when they
		 * have a udev-device. All we want to do in this case is clear the netlink.is_in_netlink
		 * flag. */

		NM_SET_OUT (out_obj_old, nmp_object_ref (obj_old));

		if (!obj_old->_link.netlink.is_in_netlink) {
			nm_assert (obj_old->_link.udev.device);
			NM_SET_OUT (out_obj_new, nmp_object_ref (obj_old));
			return NMP_CACHE_OPS_UNCHANGED;
		}

		if (!obj_old->_link.udev.device) {
			/* the update would make @obj_old invalid. Remove it. */
			_idxcache_update (cache, entry_old, NULL, FALSE, NULL);
			NM_SET_OUT (out_obj_new, NULL);
			return NMP_CACHE_OPS_REMOVED;
		}

		obj_new = nmp_object_clone (obj_old, FALSE);
		obj_new->_link.netlink.is_in_netlink = FALSE;

		_nmp_object_fixup_link_master_connected (&obj_new, NULL, cache);
		_nmp_object_fixup_link_udev_fields (&obj_new, NULL, cache->use_udev);

		_idxcache_update (cache,
		                  entry_old,
		                  obj_new,
		                  FALSE,
		                  &entry_new);
		NM_SET_OUT (out_obj_new, nmp_object_ref (entry_new->obj));
		return NMP_CACHE_OPS_UPDATED;
	}

	NM_SET_OUT (out_obj_old, nmp_object_ref (obj_old));
	NM_SET_OUT (out_obj_new, NULL);
	_idxcache_update (cache, entry_old, NULL, FALSE, NULL);
	return NMP_CACHE_OPS_REMOVED;
}

/**
 * nmp_cache_update_netlink:
 * @cache: the platform cache
 * @obj_hand_over: a #NMPObject instance as received from netlink and created via
 *    nmp_object_from_nl(). Especially for link, it must not have the udev
 *    replated fields set.
 *    This instance will be modified and might be put into the cache. When
 *    calling nmp_cache_update_netlink() you hand @obj over to the cache.
 *    Except, that the cache will increment the ref count as appropriate. You
 *    must still unref the obj to release your part of the ownership.
 * @is_dump: whether this update comes during a dump of object of the same kind.
 *    kernel dumps objects in a certain order, which matters especially for routes.
 *    Before a dump we mark all objects as dirty, and remove all untouched objects
 *    afterwards. Hence, during a dump, every update should move the object to the
 *    end of the list, to obtain the correct order. That means, to use NM_DEDUP_MULTI_IDX_MODE_APPEND_FORCE,
 *    instead of NM_DEDUP_MULTI_IDX_MODE_APPEND.
 * @out_obj_old: (allow-none) (out): return the object with same ID as @obj_hand_over,
 *    that was in the cache before update. If an object is returned, the caller must
 *    unref it afterwards.
 * @out_obj_new: (allow-none) (out): return the object from the cache after update.
 *    The caller must unref this object.
 *
 * Returns: how the cache changed.
 *
 * Even if there was no change in the cache (NMP_CACHE_OPS_UNCHANGED), @out_obj_old
 * and @out_obj_new will be set accordingly.
 **/
NMPCacheOpsType
nmp_cache_update_netlink (NMPCache *cache,
                          NMPObject *obj_hand_over,
                          gboolean is_dump,
                          const NMPObject **out_obj_old,
                          const NMPObject **out_obj_new)
{
	const NMDedupMultiEntry *entry_old;
	const NMDedupMultiEntry *entry_new;
	const NMPObject *obj_old;
	gboolean is_alive;

	nm_assert (cache);
	nm_assert (NMP_OBJECT_IS_VALID (obj_hand_over));
	nm_assert (!NMP_OBJECT_IS_STACKINIT (obj_hand_over));
	/* A link object from netlink must have the udev related fields unset.
	 * We could implement to handle that, but there is no need to support such
	 * a use-case */
	nm_assert (NMP_OBJECT_GET_TYPE (obj_hand_over) != NMP_OBJECT_TYPE_LINK ||
	           (   !obj_hand_over->_link.udev.device
	            && !obj_hand_over->link.driver));
	nm_assert (nm_dedup_multi_index_obj_find (cache->multi_idx, obj_hand_over) != obj_hand_over);

	entry_old = _lookup_entry (cache, obj_hand_over);

	if (!entry_old) {

		NM_SET_OUT (out_obj_old, NULL);

		if (!nmp_object_is_alive (obj_hand_over)) {
			NM_SET_OUT (out_obj_new, NULL);
			return NMP_CACHE_OPS_UNCHANGED;
		}

		if (NMP_OBJECT_GET_TYPE (obj_hand_over) == NMP_OBJECT_TYPE_LINK) {
			_nmp_object_fixup_link_master_connected (&obj_hand_over, NULL, cache);
			_nmp_object_fixup_link_udev_fields (&obj_hand_over, NULL, cache->use_udev);
		}

		_idxcache_update (cache,
		                  entry_old,
		                  obj_hand_over,
		                  is_dump,
		                  &entry_new);
		NM_SET_OUT (out_obj_new, nmp_object_ref (entry_new->obj));
		return NMP_CACHE_OPS_ADDED;
	}

	obj_old = entry_old->obj;

	if (NMP_OBJECT_GET_TYPE (obj_hand_over) == NMP_OBJECT_TYPE_LINK) {
		if (!obj_hand_over->_link.netlink.is_in_netlink) {
			if (!obj_old->_link.netlink.is_in_netlink) {
				nm_assert (obj_old->_link.udev.device);
				NM_SET_OUT (out_obj_old, nmp_object_ref (obj_old));
				NM_SET_OUT (out_obj_new, nmp_object_ref (obj_old));
				return NMP_CACHE_OPS_UNCHANGED;
			}
			if (obj_old->_link.udev.device) {
				/* @obj_hand_over is not in netlink.
				 *
				 * This is similar to nmp_cache_remove_netlink(), but there we preserve the
				 * preexisting netlink properties. The use case of that is when kernel_get_object()
				 * cannot load an object (based on the id of a needle).
				 *
				 * Here we keep the data provided from @obj_hand_over. The usecase is when receiving
				 * a valid @obj_hand_over instance from netlink with RTM_DELROUTE.
				 */
				is_alive = TRUE;
			} else
				is_alive = FALSE;
		} else
			is_alive = TRUE;

		if (is_alive) {
			_nmp_object_fixup_link_master_connected (&obj_hand_over, NULL, cache);

			/* Merge the netlink parts with what we have from udev. */
			udev_device_unref (obj_hand_over->_link.udev.device);
			obj_hand_over->_link.udev.device = obj_old->_link.udev.device ? udev_device_ref (obj_old->_link.udev.device) : NULL;
			_nmp_object_fixup_link_udev_fields (&obj_hand_over, NULL, cache->use_udev);

			if (obj_hand_over->_link.netlink.lnk) {
				nm_auto_nmpobj const NMPObject *lnk_old = obj_hand_over->_link.netlink.lnk;

				/* let's dedup/intern the lnk object. */
				obj_hand_over->_link.netlink.lnk = nm_dedup_multi_index_obj_intern (cache->multi_idx, lnk_old);
			}
		}
	} else
		is_alive = nmp_object_is_alive (obj_hand_over);

	NM_SET_OUT (out_obj_old, nmp_object_ref (obj_old));

	if (!is_alive) {
		/* the update would make @obj_old invalid. Remove it. */
		_idxcache_update (cache, entry_old, NULL, FALSE, NULL);
		NM_SET_OUT (out_obj_new, NULL);
		return NMP_CACHE_OPS_REMOVED;
	}

	if (nmp_object_equal (obj_old, obj_hand_over)) {
		if (is_dump)
			_idxcache_update_order_for_dump (cache, entry_old);
		nm_dedup_multi_entry_set_dirty (entry_old, FALSE);
		NM_SET_OUT (out_obj_new, nmp_object_ref (obj_old));
		return NMP_CACHE_OPS_UNCHANGED;
	}

	_idxcache_update (cache,
	                  entry_old,
	                  obj_hand_over,
	                  is_dump,
	                  &entry_new);
	NM_SET_OUT (out_obj_new, nmp_object_ref (entry_new->obj));
	return NMP_CACHE_OPS_UPDATED;
}

NMPCacheOpsType
nmp_cache_update_netlink_route (NMPCache *cache,
                                NMPObject *obj_hand_over,
                                gboolean is_dump,
                                guint16 nlmsgflags,
                                const NMPObject **out_obj_old,
                                const NMPObject **out_obj_new,
                                const NMPObject **out_obj_replace,
                                gboolean *out_resync_required)
{
	NMDedupMultiIter iter;
	const NMDedupMultiEntry *entry_old;
	const NMDedupMultiEntry *entry_new;
	const NMDedupMultiEntry *entry_cur;
	const NMDedupMultiEntry *entry_replace;
	const NMDedupMultiHeadEntry *head_entry;
	gboolean is_alive;
	NMPCacheOpsType ops_type = NMP_CACHE_OPS_UNCHANGED;
	gboolean resync_required;

	nm_assert (cache);
	nm_assert (NMP_OBJECT_IS_VALID (obj_hand_over));
	nm_assert (!NMP_OBJECT_IS_STACKINIT (obj_hand_over));
	/* A link object from netlink must have the udev related fields unset.
	 * We could implement to handle that, but there is no need to support such
	 * a use-case */
	nm_assert (NM_IN_SET (NMP_OBJECT_GET_TYPE (obj_hand_over), NMP_OBJECT_TYPE_IP4_ROUTE,
	                                                           NMP_OBJECT_TYPE_IP6_ROUTE));
	nm_assert (nm_dedup_multi_index_obj_find (cache->multi_idx, obj_hand_over) != obj_hand_over);

	entry_old = _lookup_entry (cache, obj_hand_over);
	entry_new = NULL;

	NM_SET_OUT (out_obj_old, nmp_object_ref (nm_dedup_multi_entry_get_obj (entry_old)));

	if (!entry_old) {

		if (!nmp_object_is_alive (obj_hand_over))
			goto update_done;

		_idxcache_update (cache,
		                  NULL,
		                  obj_hand_over,
		                  is_dump,
		                  &entry_new);
		ops_type = NMP_CACHE_OPS_ADDED;
		goto update_done;
	}

	is_alive = nmp_object_is_alive (obj_hand_over);

	if (!is_alive) {
		/* the update would make @entry_old invalid. Remove it. */
		_idxcache_update (cache, entry_old, NULL, FALSE, NULL);
		ops_type = NMP_CACHE_OPS_REMOVED;
		goto update_done;
	}

	if (nmp_object_equal (entry_old->obj, obj_hand_over)) {
		if (is_dump)
			_idxcache_update_order_for_dump (cache, entry_old);
		nm_dedup_multi_entry_set_dirty (entry_old, FALSE);
		goto update_done;
	}

	_idxcache_update (cache,
	                  entry_old,
	                  obj_hand_over,
	                  is_dump,
	                  &entry_new);
	ops_type = NMP_CACHE_OPS_UPDATED;

update_done:
	NM_SET_OUT (out_obj_new, nmp_object_ref (nm_dedup_multi_entry_get_obj (entry_new)));

	/* a RTM_GETROUTE event may signal that another object was replaced.
	 * Find out whether that is the case and return it as @obj_replaced.
	 *
	 * Also, fixup the order of @entry_new within NMP_CACHE_ID_TYPE_ROUTES_BY_WEAK_ID
	 * index. For most parts, we don't care about the order of objects (including routes).
	 * But NMP_CACHE_ID_TYPE_ROUTES_BY_WEAK_ID we must keep in the correct order, to
	 * properly find @obj_replaced. */
	resync_required = FALSE;
	entry_replace = NULL;
	if (is_dump)
		goto out;

	if (!entry_new) {
		if (   NM_FLAGS_HAS (nlmsgflags, NLM_F_REPLACE)
		    && nmp_cache_lookup_all (cache,
		                             NMP_CACHE_ID_TYPE_ROUTES_BY_WEAK_ID,
		                             obj_hand_over)) {
			/* hm. @obj_hand_over was not added, meaning it was not alive.
			 * However, we track some other objects with the same weak-id.
			 * It's unclear what that means. To be sure, resync. */
			resync_required = TRUE;
		}
		goto out;
	}

	/* FIXME: for routes, we only maintain the order correctly for the BY_WEAK_ID
	 * index. For all other indexes their order becomes messed up. */
	entry_cur = _lookup_entry_with_idx_type (cache,
	                                         NMP_CACHE_ID_TYPE_ROUTES_BY_WEAK_ID,
	                                         entry_new->obj);
	if (!entry_cur) {
		nm_assert_not_reached ();
		goto out;
	}
	nm_assert (entry_cur->obj == entry_new->obj);

	head_entry = entry_cur->head;
	nm_assert (head_entry == nmp_cache_lookup_all (cache,
	                                               NMP_CACHE_ID_TYPE_ROUTES_BY_WEAK_ID,
	                                               entry_cur->obj));

	if (head_entry->len == 1) {
		/* there is only one object, and we expect it to be @obj_new. */
		nm_assert (nm_dedup_multi_head_entry_get_idx (head_entry, 0) == entry_cur);
		goto out;
	}

	switch (nlmsgflags & (NLM_F_REPLACE | NLM_F_EXCL | NLM_F_CREATE | NLM_F_APPEND)) {
	case NLM_F_REPLACE:
		/* ip route change */

		/* get the first element (but skip @obj_new). */
		nm_dedup_multi_iter_init (&iter, head_entry);
		if (!nm_dedup_multi_iter_next (&iter))
			nm_assert_not_reached ();
		if (iter.current == entry_cur) {
			if (!nm_dedup_multi_iter_next (&iter))
				nm_assert_not_reached ();
		}
		entry_replace = iter.current;

		nm_assert (   entry_replace
		           && entry_cur != entry_replace);

		nm_dedup_multi_entry_reorder (entry_cur, entry_replace, FALSE);
		break;
	case NLM_F_CREATE | NLM_F_APPEND:
		/* ip route append */
		nm_dedup_multi_entry_reorder (entry_cur, NULL, TRUE);
		break;
	case NLM_F_CREATE:
		/* ip route prepend */
		nm_dedup_multi_entry_reorder (entry_cur, NULL, FALSE);
		break;
	default:
		/* this is an unexpected case, probably a bug that we need to handle better. */
		resync_required = TRUE;
		break;
	}

out:
	NM_SET_OUT (out_obj_replace, nmp_object_ref (nm_dedup_multi_entry_get_obj (entry_replace)));
	NM_SET_OUT (out_resync_required, resync_required);
	return ops_type;
}

NMPCacheOpsType
nmp_cache_update_link_udev (NMPCache *cache,
                            int ifindex,
                            struct udev_device *udevice,
                            const NMPObject **out_obj_old,
                            const NMPObject **out_obj_new)
{
	const NMPObject *obj_old;
	nm_auto_nmpobj NMPObject *obj_new = NULL;
	const NMDedupMultiEntry *entry_old;
	const NMDedupMultiEntry *entry_new;

	entry_old = nmp_cache_lookup_entry_link (cache, ifindex);

	if (!entry_old) {
		if (!udevice) {
			NM_SET_OUT (out_obj_old, NULL);
			NM_SET_OUT (out_obj_new, NULL);
			return NMP_CACHE_OPS_UNCHANGED;
		}

		obj_new = nmp_object_new (NMP_OBJECT_TYPE_LINK, NULL);
		obj_new->link.ifindex = ifindex;
		obj_new->_link.udev.device = udev_device_ref (udevice);

		_nmp_object_fixup_link_udev_fields (&obj_new, NULL, cache->use_udev);

		_idxcache_update (cache,
		                  NULL,
		                  obj_new,
		                  FALSE,
		                  &entry_new);
		NM_SET_OUT (out_obj_old, NULL);
		NM_SET_OUT (out_obj_new, nmp_object_ref (entry_new->obj));
		return NMP_CACHE_OPS_ADDED;
	} else {
		obj_old = entry_old->obj;
		NM_SET_OUT (out_obj_old, nmp_object_ref (obj_old));

		if (obj_old->_link.udev.device == udevice) {
			NM_SET_OUT (out_obj_new, nmp_object_ref (obj_old));
			return NMP_CACHE_OPS_UNCHANGED;
		}

		if (!udevice && !obj_old->_link.netlink.is_in_netlink) {
			/* the update would make @obj_old invalid. Remove it. */
			_idxcache_update (cache, entry_old, NULL, FALSE, NULL);
			NM_SET_OUT (out_obj_new, NULL);
			return NMP_CACHE_OPS_REMOVED;
		}

		obj_new = nmp_object_clone (obj_old, FALSE);

		udev_device_unref (obj_new->_link.udev.device);
		obj_new->_link.udev.device = udevice ? udev_device_ref (udevice) : NULL;

		_nmp_object_fixup_link_udev_fields (&obj_new, NULL, cache->use_udev);

		_idxcache_update (cache,
		                  entry_old,
		                  obj_new,
		                  FALSE,
		                  &entry_new);
		NM_SET_OUT (out_obj_new, nmp_object_ref (entry_new->obj));
		return NMP_CACHE_OPS_UPDATED;
	}
}

NMPCacheOpsType
nmp_cache_update_link_master_connected (NMPCache *cache,
                                        int ifindex,
                                        const NMPObject **out_obj_old,
                                        const NMPObject **out_obj_new)
{
	const NMDedupMultiEntry *entry_old;
	const NMDedupMultiEntry *entry_new = NULL;
	const NMPObject *obj_old;
	nm_auto_nmpobj NMPObject *obj_new = NULL;

	entry_old = nmp_cache_lookup_entry_link (cache, ifindex);

	if (!entry_old) {
		NM_SET_OUT (out_obj_old, NULL);
		NM_SET_OUT (out_obj_new, NULL);
		return NMP_CACHE_OPS_UNCHANGED;
	}

	obj_old = entry_old->obj;

	if (!nmp_cache_link_connected_needs_toggle (cache, obj_old, NULL, NULL)) {
		NM_SET_OUT (out_obj_old, nmp_object_ref (obj_old));
		NM_SET_OUT (out_obj_new, nmp_object_ref (obj_old));
		return NMP_CACHE_OPS_UNCHANGED;
	}

	obj_new = nmp_object_clone (obj_old, FALSE);
	obj_new->link.connected = !obj_old->link.connected;

	NM_SET_OUT (out_obj_old, nmp_object_ref (obj_old));
	_idxcache_update (cache,
	                  entry_old,
	                  obj_new,
	                  FALSE,
	                  &entry_new);
	NM_SET_OUT (out_obj_new, nmp_object_ref (entry_new->obj));
	return NMP_CACHE_OPS_UPDATED;
}

/*****************************************************************************/

void
nmp_cache_dirty_set_all_main (NMPCache *cache,
                              const NMPLookup *lookup)
{
	const NMDedupMultiHeadEntry *head_entry;
	NMDedupMultiIter iter;

	nm_assert (cache);
	nm_assert (lookup);

	head_entry = nmp_cache_lookup (cache, lookup);

	nm_dedup_multi_iter_init (&iter, head_entry);
	while (nm_dedup_multi_iter_next (&iter)) {
		const NMDedupMultiEntry *main_entry;

		main_entry = nmp_cache_reresolve_main_entry (cache, iter.current, lookup);

		nm_dedup_multi_entry_set_dirty (main_entry, TRUE);
	}
}

/*****************************************************************************/

NMPCache *
nmp_cache_new (NMDedupMultiIndex *multi_idx, gboolean use_udev)
{
	NMPCache *cache = g_slice_new0 (NMPCache);
	guint i;

	for (i = NMP_CACHE_ID_TYPE_NONE + 1; i <= NMP_CACHE_ID_TYPE_MAX; i++)
		_dedup_multi_idx_type_init ((DedupMultiIdxType *) _idx_type_get (cache, i), i);

	cache->multi_idx = nm_dedup_multi_index_ref (multi_idx);

	cache->use_udev = !!use_udev;
	return cache;
}

void
nmp_cache_free (NMPCache *cache)
{
	guint i;

	for (i = NMP_CACHE_ID_TYPE_NONE + 1; i <= NMP_CACHE_ID_TYPE_MAX; i++)
		nm_dedup_multi_index_remove_idx (cache->multi_idx, _idx_type_get (cache, i));

	nm_dedup_multi_index_unref (cache->multi_idx);

	g_slice_free (NMPCache, cache);
}

/*****************************************************************************/

void
ASSERT_nmp_cache_is_consistent (const NMPCache *cache)
{
}

/*****************************************************************************/

const NMPClass _nmp_classes[NMP_OBJECT_TYPE_MAX] = {
	[NMP_OBJECT_TYPE_LINK - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_LINK,
		.sizeof_data                        = sizeof (NMPObjectLink),
		.sizeof_public                      = sizeof (NMPlatformLink),
		.obj_type_name                      = "link",
		.rtm_gettype                        = RTM_GETLINK,
		.signal_type_id                     = NM_PLATFORM_SIGNAL_ID_LINK,
		.signal_type                        = NM_PLATFORM_SIGNAL_LINK_CHANGED,
		.supported_cache_ids                = _supported_cache_ids_link,
		.cmd_obj_hash_update                = _vt_cmd_obj_hash_update_link,
		.cmd_obj_cmp                        = _vt_cmd_obj_cmp_link,
		.cmd_obj_copy                       = _vt_cmd_obj_copy_link,
		.cmd_obj_dispose                    = _vt_cmd_obj_dispose_link,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_link,
		.cmd_obj_is_visible                 = _vt_cmd_obj_is_visible_link,
		.cmd_obj_to_string                  = _vt_cmd_obj_to_string_link,
		.cmd_plobj_id_copy                  = _vt_cmd_plobj_id_copy_link,
		.cmd_plobj_id_cmp                   = _vt_cmd_plobj_id_cmp_link,
		.cmd_plobj_id_hash_update           = _vt_cmd_plobj_id_hash_update_link,
		.cmd_plobj_to_string_id             = _vt_cmd_plobj_to_string_id_link,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_link_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_link_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_link_cmp,
	},
	[NMP_OBJECT_TYPE_IP4_ADDRESS - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_IP4_ADDRESS,
		.sizeof_data                        = sizeof (NMPObjectIP4Address),
		.sizeof_public                      = sizeof (NMPlatformIP4Address),
		.obj_type_name                      = "ip4-address",
		.addr_family                        = AF_INET,
		.rtm_gettype                        = RTM_GETADDR,
		.signal_type_id                     = NM_PLATFORM_SIGNAL_ID_IP4_ADDRESS,
		.signal_type                        = NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED,
		.supported_cache_ids                = _supported_cache_ids_ipx_address,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_ipx_address,
		.cmd_plobj_id_copy                  = _vt_cmd_plobj_id_copy_ip4_address,
		.cmd_plobj_id_cmp                   = _vt_cmd_plobj_id_cmp_ip4_address,
		.cmd_plobj_id_hash_update           = _vt_cmd_plobj_id_hash_update_ip4_address,
		.cmd_plobj_to_string_id             = _vt_cmd_plobj_to_string_id_ip4_address,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_ip4_address_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_ip4_address_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_ip4_address_cmp,
	},
	[NMP_OBJECT_TYPE_IP6_ADDRESS - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_IP6_ADDRESS,
		.sizeof_data                        = sizeof (NMPObjectIP6Address),
		.sizeof_public                      = sizeof (NMPlatformIP6Address),
		.obj_type_name                      = "ip6-address",
		.addr_family                        = AF_INET6,
		.rtm_gettype                        = RTM_GETADDR,
		.signal_type_id                     = NM_PLATFORM_SIGNAL_ID_IP6_ADDRESS,
		.signal_type                        = NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED,
		.supported_cache_ids                = _supported_cache_ids_ipx_address,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_ipx_address,
		.cmd_plobj_id_copy                  = _vt_cmd_plobj_id_copy_ip6_address,
		.cmd_plobj_id_cmp                   = _vt_cmd_plobj_id_cmp_ip6_address,
		.cmd_plobj_id_hash_update           = _vt_cmd_plobj_id_hash_update_ip6_address,
		.cmd_plobj_to_string_id             = _vt_cmd_plobj_to_string_id_ip6_address,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_ip6_address_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_ip6_address_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_ip6_address_cmp
	},
	[NMP_OBJECT_TYPE_IP4_ROUTE - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_IP4_ROUTE,
		.sizeof_data                        = sizeof (NMPObjectIP4Route),
		.sizeof_public                      = sizeof (NMPlatformIP4Route),
		.obj_type_name                      = "ip4-route",
		.addr_family                        = AF_INET,
		.rtm_gettype                        = RTM_GETROUTE,
		.signal_type_id                     = NM_PLATFORM_SIGNAL_ID_IP4_ROUTE,
		.signal_type                        = NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED,
		.supported_cache_ids                = _supported_cache_ids_ipx_route,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_ipx_route,
		.cmd_plobj_id_copy                  = _vt_cmd_plobj_id_copy_ip4_route,
		.cmd_plobj_id_cmp                   = _vt_cmd_plobj_id_cmp_ip4_route,
		.cmd_plobj_id_hash_update           = _vt_cmd_plobj_id_hash_update_ip4_route,
		.cmd_plobj_to_string_id             = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_ip4_route_to_string,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_ip4_route_to_string,
		.cmd_plobj_hash_update              = _vt_cmd_plobj_hash_update_ip4_route,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_ip4_route_cmp_full,
	},
	[NMP_OBJECT_TYPE_IP6_ROUTE - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_IP6_ROUTE,
		.sizeof_data                        = sizeof (NMPObjectIP6Route),
		.sizeof_public                      = sizeof (NMPlatformIP6Route),
		.obj_type_name                      = "ip6-route",
		.addr_family                        = AF_INET6,
		.rtm_gettype                        = RTM_GETROUTE,
		.signal_type_id                     = NM_PLATFORM_SIGNAL_ID_IP6_ROUTE,
		.signal_type                        = NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED,
		.supported_cache_ids                = _supported_cache_ids_ipx_route,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_ipx_route,
		.cmd_plobj_id_copy                  = _vt_cmd_plobj_id_copy_ip6_route,
		.cmd_plobj_id_cmp                   = _vt_cmd_plobj_id_cmp_ip6_route,
		.cmd_plobj_id_hash_update           = _vt_cmd_plobj_id_hash_update_ip6_route,
		.cmd_plobj_to_string_id             = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_ip6_route_to_string,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_ip6_route_to_string,
		.cmd_plobj_hash_update              = _vt_cmd_plobj_hash_update_ip6_route,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_ip6_route_cmp_full,
	},
	[NMP_OBJECT_TYPE_ROUTING_RULE - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_ROUTING_RULE,
		.sizeof_data                        = sizeof (NMPObjectRoutingRule),
		.sizeof_public                      = sizeof (NMPlatformRoutingRule),
		.obj_type_name                      = "routing-rule",
		.rtm_gettype                        = RTM_GETRULE,
		.signal_type_id                     = NM_PLATFORM_SIGNAL_ID_ROUTING_RULE,
		.signal_type                        = NM_PLATFORM_SIGNAL_ROUTING_RULE_CHANGED,
		.supported_cache_ids                = _supported_cache_ids_routing_rules,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_routing_rule,
		.cmd_plobj_id_copy                  = _vt_cmd_plobj_id_copy_routing_rule,
		.cmd_plobj_id_cmp                   = _vt_cmd_plobj_id_cmp_routing_rule,
		.cmd_plobj_id_hash_update           = _vt_cmd_plobj_id_hash_update_routing_rule,
		.cmd_plobj_to_string_id             = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_routing_rule_to_string,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_routing_rule_to_string,
		.cmd_plobj_hash_update              = _vt_cmd_plobj_hash_update_routing_rule,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_routing_rule_cmp_full,
	},
	[NMP_OBJECT_TYPE_QDISC - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_QDISC,
		.sizeof_data                        = sizeof (NMPObjectQdisc),
		.sizeof_public                      = sizeof (NMPlatformQdisc),
		.obj_type_name                      = "qdisc",
		.rtm_gettype                        = RTM_GETQDISC,
		.signal_type_id                     = NM_PLATFORM_SIGNAL_ID_QDISC,
		.signal_type                        = NM_PLATFORM_SIGNAL_QDISC_CHANGED,
		.supported_cache_ids                = _supported_cache_ids_object,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_qdisc,
		.cmd_plobj_id_cmp                   = _vt_cmd_plobj_id_cmp_qdisc,
		.cmd_plobj_id_hash_update           = _vt_cmd_plobj_id_hash_update_qdisc,
		.cmd_plobj_to_string_id             = _vt_cmd_plobj_to_string_id_qdisc,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_qdisc_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_qdisc_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_qdisc_cmp,
	},
	[NMP_OBJECT_TYPE_TFILTER - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_TFILTER,
		.sizeof_data                        = sizeof (NMPObjectTfilter),
		.sizeof_public                      = sizeof (NMPlatformTfilter),
		.obj_type_name                      = "tfilter",
		.rtm_gettype                        = RTM_GETTFILTER,
		.signal_type_id                     = NM_PLATFORM_SIGNAL_ID_TFILTER,
		.signal_type                        = NM_PLATFORM_SIGNAL_TFILTER_CHANGED,
		.supported_cache_ids                = _supported_cache_ids_object,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_tfilter,
		.cmd_plobj_id_cmp                   = _vt_cmd_plobj_id_cmp_tfilter,
		.cmd_plobj_id_hash_update           = _vt_cmd_plobj_id_hash_update_tfilter,
		.cmd_plobj_to_string_id             = _vt_cmd_plobj_to_string_id_tfilter,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_tfilter_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_tfilter_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_tfilter_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_GRE - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_LNK_GRE,
		.sizeof_data                        = sizeof (NMPObjectLnkGre),
		.sizeof_public                      = sizeof (NMPlatformLnkGre),
		.obj_type_name                      = "gre",
		.lnk_link_type                      = NM_LINK_TYPE_GRE,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_gre_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_lnk_gre_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_gre_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_GRETAP - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_LNK_GRETAP,
		.sizeof_data                        = sizeof (NMPObjectLnkGre),
		.sizeof_public                      = sizeof (NMPlatformLnkGre),
		.obj_type_name                      = "gretap",
		.lnk_link_type                      = NM_LINK_TYPE_GRETAP,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_gre_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_lnk_gre_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_gre_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_INFINIBAND - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_LNK_INFINIBAND,
		.sizeof_data                        = sizeof (NMPObjectLnkInfiniband),
		.sizeof_public                      = sizeof (NMPlatformLnkInfiniband),
		.obj_type_name                      = "infiniband",
		.lnk_link_type                      = NM_LINK_TYPE_INFINIBAND,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_infiniband_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_lnk_infiniband_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_infiniband_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_IP6TNL - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_LNK_IP6TNL,
		.sizeof_data                        = sizeof (NMPObjectLnkIp6Tnl),
		.sizeof_public                      = sizeof (NMPlatformLnkIp6Tnl),
		.obj_type_name                      = "ip6tnl",
		.lnk_link_type                      = NM_LINK_TYPE_IP6TNL,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_ip6tnl_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_lnk_ip6tnl_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_ip6tnl_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_IP6GRE - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_LNK_IP6GRE,
		.sizeof_data                        = sizeof (NMPObjectLnkIp6Tnl),
		.sizeof_public                      = sizeof (NMPlatformLnkIp6Tnl),
		.obj_type_name                      = "ip6gre",
		.lnk_link_type                      = NM_LINK_TYPE_IP6GRE,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_ip6tnl_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_lnk_ip6tnl_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_ip6tnl_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_IP6GRETAP - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_LNK_IP6GRETAP,
		.sizeof_data                        = sizeof (NMPObjectLnkIp6Tnl),
		.sizeof_public                      = sizeof (NMPlatformLnkIp6Tnl),
		.obj_type_name                      = "ip6gretap",
		.lnk_link_type                      = NM_LINK_TYPE_IP6GRETAP,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_ip6tnl_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_lnk_ip6tnl_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_ip6tnl_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_IPIP - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_LNK_IPIP,
		.sizeof_data                        = sizeof (NMPObjectLnkIpIp),
		.sizeof_public                      = sizeof (NMPlatformLnkIpIp),
		.obj_type_name                      = "ipip",
		.lnk_link_type                      = NM_LINK_TYPE_IPIP,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_ipip_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_lnk_ipip_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_ipip_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_MACSEC - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_LNK_MACSEC,
		.sizeof_data                        = sizeof (NMPObjectLnkMacsec),
		.sizeof_public                      = sizeof (NMPlatformLnkMacsec),
		.obj_type_name                      = "macsec",
		.lnk_link_type                      = NM_LINK_TYPE_MACSEC,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_macsec_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_lnk_macsec_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_macsec_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_MACVLAN - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_LNK_MACVLAN,
		.sizeof_data                        = sizeof (NMPObjectLnkMacvlan),
		.sizeof_public                      = sizeof (NMPlatformLnkMacvlan),
		.obj_type_name                      = "macvlan",
		.lnk_link_type                      = NM_LINK_TYPE_MACVLAN,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_macvlan_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_lnk_macvlan_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_macvlan_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_MACVTAP - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_LNK_MACVTAP,
		.sizeof_data                        = sizeof (NMPObjectLnkMacvtap),
		.sizeof_public                      = sizeof (NMPlatformLnkMacvtap),
		.obj_type_name                      = "macvtap",
		.lnk_link_type                      = NM_LINK_TYPE_MACVTAP,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_macvlan_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_lnk_macvlan_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_macvlan_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_SIT - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_LNK_SIT,
		.sizeof_data                        = sizeof (NMPObjectLnkSit),
		.sizeof_public                      = sizeof (NMPlatformLnkSit),
		.obj_type_name                      = "sit",
		.lnk_link_type                      = NM_LINK_TYPE_SIT,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_sit_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_lnk_sit_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_sit_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_TUN - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_LNK_TUN,
		.sizeof_data                        = sizeof (NMPObjectLnkTun),
		.sizeof_public                      = sizeof (NMPlatformLnkTun),
		.obj_type_name                      = "tun",
		.lnk_link_type                      = NM_LINK_TYPE_TUN,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_tun_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_lnk_tun_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_tun_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_VLAN - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_LNK_VLAN,
		.sizeof_data                        = sizeof (NMPObjectLnkVlan),
		.sizeof_public                      = sizeof (NMPlatformLnkVlan),
		.obj_type_name                      = "vlan",
		.lnk_link_type                      = NM_LINK_TYPE_VLAN,
		.cmd_obj_hash_update                = _vt_cmd_obj_hash_update_lnk_vlan,
		.cmd_obj_cmp                        = _vt_cmd_obj_cmp_lnk_vlan,
		.cmd_obj_copy                       = _vt_cmd_obj_copy_lnk_vlan,
		.cmd_obj_dispose                    = _vt_cmd_obj_dispose_lnk_vlan,
		.cmd_obj_to_string                  = _vt_cmd_obj_to_string_lnk_vlan,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_vlan_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_lnk_vlan_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_vlan_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_VXLAN - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_LNK_VXLAN,
		.sizeof_data                        = sizeof (NMPObjectLnkVxlan),
		.sizeof_public                      = sizeof (NMPlatformLnkVxlan),
		.obj_type_name                      = "vxlan",
		.lnk_link_type                      = NM_LINK_TYPE_VXLAN,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_vxlan_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_lnk_vxlan_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_vxlan_cmp,
	},
	[NMP_OBJECT_TYPE_LNK_WIREGUARD - 1] = {
		.parent                             = DEDUP_MULTI_OBJ_CLASS_INIT(),
		.obj_type                           = NMP_OBJECT_TYPE_LNK_WIREGUARD,
		.sizeof_data                        = sizeof (NMPObjectLnkWireGuard),
		.sizeof_public                      = sizeof (NMPlatformLnkWireGuard),
		.obj_type_name                      = "wireguard",
		.lnk_link_type                      = NM_LINK_TYPE_WIREGUARD,
		.cmd_obj_hash_update                = _vt_cmd_obj_hash_update_lnk_wireguard,
		.cmd_obj_cmp                        = _vt_cmd_obj_cmp_lnk_wireguard,
		.cmd_obj_copy                       = _vt_cmd_obj_copy_lnk_wireguard,
		.cmd_obj_dispose                    = _vt_cmd_obj_dispose_lnk_wireguard,
		.cmd_obj_to_string                  = _vt_cmd_obj_to_string_lnk_wireguard,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj, char *buf, gsize len)) nm_platform_lnk_wireguard_to_string,
		.cmd_plobj_hash_update              = (void (*) (const NMPlatformObject *obj, NMHashState *h)) nm_platform_lnk_wireguard_hash_update,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_lnk_wireguard_cmp,
	},
};
