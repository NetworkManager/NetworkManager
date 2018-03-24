/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * Copyright (C) 2005 - 2017 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-ip4-config.h"

#include <string.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <linux/rtnetlink.h>

#include "nm-utils/nm-dedup-multi.h"

#include "nm-utils.h"
#include "platform/nmp-object.h"
#include "platform/nm-platform.h"
#include "platform/nm-platform-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-core-internal.h"
#include "nm-dbus-object.h"

/*****************************************************************************/

/* internal guint32 are assigned to gobject properties of type uint. Ensure, that uint is large enough */
G_STATIC_ASSERT (sizeof (uint) >= sizeof (guint32));
G_STATIC_ASSERT (G_MAXUINT >= 0xFFFFFFFF);

/*****************************************************************************/

static gboolean
_route_valid (const NMPlatformIP4Route *r)
{
	return    r
	       && r->plen <= 32
	       && r->network == nm_utils_ip4_address_clear_host_address (r->network, r->plen);
}

/*****************************************************************************/

static void
_idx_obj_id_hash_update (const NMDedupMultiIdxType *idx_type,
                         const NMDedupMultiObj *obj,
                         NMHashState *h)
{
	nmp_object_id_hash_update ((NMPObject *) obj, h);
}

static gboolean
_idx_obj_id_equal (const NMDedupMultiIdxType *idx_type,
                   const NMDedupMultiObj *obj_a,
                   const NMDedupMultiObj *obj_b)
{
	return nmp_object_id_equal ((NMPObject *) obj_a, (NMPObject *) obj_b);
}

void
nm_ip_config_dedup_multi_idx_type_init (NMIPConfigDedupMultiIdxType *idx_type,
                                        NMPObjectType obj_type)
{
	static const NMDedupMultiIdxTypeClass idx_type_class = {
		.idx_obj_id_hash_update = _idx_obj_id_hash_update,
		.idx_obj_id_equal = _idx_obj_id_equal,
	};

	nm_dedup_multi_idx_type_init ((NMDedupMultiIdxType *) idx_type,
	                              &idx_type_class);
	idx_type->obj_type = obj_type;
}

/*****************************************************************************/

gboolean
_nm_ip_config_add_obj (NMDedupMultiIndex *multi_idx,
                       NMIPConfigDedupMultiIdxType *idx_type,
                       int ifindex,
                       const NMPObject *obj_new,
                       const NMPlatformObject *pl_new,
                       gboolean merge,
                       gboolean append_force,
                       const NMPObject **out_obj_old /* returns a reference! */,
                       const NMPObject **out_obj_new /* does not return a reference */)
{
	NMPObject obj_new_stackinit;
	const NMDedupMultiEntry *entry_old;
	const NMDedupMultiEntry *entry_new;

	nm_assert (multi_idx);
	nm_assert (idx_type);
	nm_assert (NM_IN_SET (idx_type->obj_type, NMP_OBJECT_TYPE_IP4_ADDRESS,
	                                          NMP_OBJECT_TYPE_IP4_ROUTE,
	                                          NMP_OBJECT_TYPE_IP6_ADDRESS,
	                                          NMP_OBJECT_TYPE_IP6_ROUTE));
	nm_assert (ifindex > 0);

	/* we go through extra lengths to accept a full obj_new object. That one,
	 * can be reused by increasing the ref-count. */
	if (!obj_new) {
		nm_assert (pl_new);
		obj_new = nmp_object_stackinit (&obj_new_stackinit, idx_type->obj_type, pl_new);
		obj_new_stackinit.object.ifindex = ifindex;
	} else {
		nm_assert (!pl_new);
		nm_assert (NMP_OBJECT_GET_TYPE (obj_new) == idx_type->obj_type);
		if (obj_new->object.ifindex != ifindex) {
			obj_new = nmp_object_stackinit_obj (&obj_new_stackinit, obj_new);
			obj_new_stackinit.object.ifindex = ifindex;
		}
	}
	nm_assert (NMP_OBJECT_GET_TYPE (obj_new) == idx_type->obj_type);
	nm_assert (nmp_object_is_alive (obj_new));

	entry_old = nm_dedup_multi_index_lookup_obj (multi_idx, &idx_type->parent, obj_new);

	if (entry_old) {
		gboolean modified = FALSE;
		const NMPObject *obj_old = entry_old->obj;

		if (nmp_object_equal (obj_new, obj_old)) {
			nm_dedup_multi_entry_set_dirty (entry_old, FALSE);
			goto append_force_and_out;
		}

		/* if @merge, we merge the new object with the existing one.
		 * Otherwise, we replace it entirely. */
		if (merge) {
			switch (idx_type->obj_type) {
			case NMP_OBJECT_TYPE_IP4_ADDRESS:
			case NMP_OBJECT_TYPE_IP6_ADDRESS:
				/* for addresses that we read from the kernel, we keep the timestamps as defined
				 * by the previous source (item_old). The reason is, that the other source configured the lifetimes
				 * with "what should be" and the kernel values are "what turned out after configuring it".
				 *
				 * For other sources, the longer lifetime wins. */
				if (   (   obj_new->ip_address.addr_source == NM_IP_CONFIG_SOURCE_KERNEL
				        && obj_old->ip_address.addr_source != NM_IP_CONFIG_SOURCE_KERNEL)
				    || nm_platform_ip_address_cmp_expiry (NMP_OBJECT_CAST_IP_ADDRESS (obj_old), NMP_OBJECT_CAST_IP_ADDRESS(obj_new)) > 0) {
					obj_new = nmp_object_stackinit_obj (&obj_new_stackinit, obj_new);
					obj_new_stackinit.ip_address.timestamp = NMP_OBJECT_CAST_IP_ADDRESS (obj_old)->timestamp;
					obj_new_stackinit.ip_address.lifetime  = NMP_OBJECT_CAST_IP_ADDRESS (obj_old)->lifetime;
					obj_new_stackinit.ip_address.preferred = NMP_OBJECT_CAST_IP_ADDRESS (obj_old)->preferred;
					modified = TRUE;
				}

				/* keep the maximum addr_source. */
				if (obj_new->ip_address.addr_source < obj_old->ip_address.addr_source) {
					obj_new = nmp_object_stackinit_obj (&obj_new_stackinit, obj_new);
					obj_new_stackinit.ip_address.addr_source = obj_old->ip_address.addr_source;
					modified = TRUE;
				}
				break;
			case NMP_OBJECT_TYPE_IP4_ROUTE:
			case NMP_OBJECT_TYPE_IP6_ROUTE:
				/* keep the maximum rt_source. */
				if (obj_new->ip_route.rt_source < obj_old->ip_route.rt_source) {
					obj_new = nmp_object_stackinit_obj (&obj_new_stackinit, obj_new);
					obj_new_stackinit.ip_route.rt_source = obj_old->ip_route.rt_source;
					modified = TRUE;
				}
				break;
			default:
				nm_assert_not_reached ();
				break;
			}

			if (   modified
			    && nmp_object_equal (obj_new, obj_old)) {
				nm_dedup_multi_entry_set_dirty (entry_old, FALSE);
				goto append_force_and_out;
			}
		}
	}

	if (!nm_dedup_multi_index_add_full (multi_idx,
	                                    &idx_type->parent,
	                                    obj_new,
	                                    NM_DEDUP_MULTI_IDX_MODE_APPEND,
	                                    NULL,
	                                    entry_old ?: NM_DEDUP_MULTI_ENTRY_MISSING,
	                                    NULL,
	                                    &entry_new,
	                                    out_obj_old)) {
		nm_assert_not_reached ();
		NM_SET_OUT (out_obj_new, NULL);
		return FALSE;
	}

	NM_SET_OUT (out_obj_new, entry_new->obj);
	return TRUE;

append_force_and_out:
	NM_SET_OUT (out_obj_old, nmp_object_ref (entry_old->obj));
	NM_SET_OUT (out_obj_new, entry_old->obj);
	if (append_force) {
		if (nm_dedup_multi_entry_reorder (entry_old, NULL, TRUE))
			return TRUE;
	}
	return FALSE;
}

/**
 * _nm_ip_config_lookup_ip_route:
 * @multi_idx:
 * @idx_type:
 * @needle:
 * @cmp_type: after lookup, filter the result by comparing with @cmp_type. Only
 *   return the result, if it compares equal to @needle according to this @cmp_type.
 *   Note that the index uses %NM_PLATFORM_IP_ROUTE_CMP_TYPE_DST type, so passing
 *   that compare-type means not to filter any further.
 *
 * Returns: the found entry or %NULL.
 */
const NMDedupMultiEntry *
_nm_ip_config_lookup_ip_route (const NMDedupMultiIndex *multi_idx,
                               const NMIPConfigDedupMultiIdxType *idx_type,
                               const NMPObject *needle,
                               NMPlatformIPRouteCmpType cmp_type)
{
	const NMDedupMultiEntry *entry;

	nm_assert (multi_idx);
	nm_assert (idx_type);
	nm_assert (NM_IN_SET (idx_type->obj_type, NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE));
	nm_assert (NMP_OBJECT_GET_TYPE (needle) == idx_type->obj_type);

	entry = nm_dedup_multi_index_lookup_obj (multi_idx,
	                                         &idx_type->parent,
	                                         needle);
	if (!entry)
		return NULL;

	if (cmp_type == NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID) {
		nm_assert (   (   NMP_OBJECT_GET_TYPE (needle) == NMP_OBJECT_TYPE_IP4_ROUTE
		               && nm_platform_ip4_route_cmp (NMP_OBJECT_CAST_IP4_ROUTE (entry->obj), NMP_OBJECT_CAST_IP4_ROUTE (needle), cmp_type) == 0)
		           || (   NMP_OBJECT_GET_TYPE (needle) == NMP_OBJECT_TYPE_IP6_ROUTE
		               && nm_platform_ip6_route_cmp (NMP_OBJECT_CAST_IP6_ROUTE (entry->obj), NMP_OBJECT_CAST_IP6_ROUTE (needle), cmp_type) == 0));
	} else {
		if (NMP_OBJECT_GET_TYPE (needle) == NMP_OBJECT_TYPE_IP4_ROUTE) {
			if (nm_platform_ip4_route_cmp (NMP_OBJECT_CAST_IP4_ROUTE (entry->obj),
			                               NMP_OBJECT_CAST_IP4_ROUTE (needle),
			                               cmp_type) != 0)
				return NULL;
		} else {
			if (nm_platform_ip6_route_cmp (NMP_OBJECT_CAST_IP6_ROUTE (entry->obj),
			                               NMP_OBJECT_CAST_IP6_ROUTE (needle),
			                               cmp_type) != 0)
				return NULL;
		}
	}
	return entry;
}

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMIP4Config,
	PROP_MULTI_IDX,
	PROP_IFINDEX,
	PROP_ADDRESS_DATA,
	PROP_ADDRESSES,
	PROP_ROUTE_DATA,
	PROP_ROUTES,
	PROP_GATEWAY,
	PROP_NAMESERVERS,
	PROP_DOMAINS,
	PROP_SEARCHES,
	PROP_DNS_OPTIONS,
	PROP_WINS_SERVERS,
	PROP_DNS_PRIORITY,
);

typedef struct {
	bool metered:1;
	guint32 mtu;
	int ifindex;
	NMIPConfigSource mtu_source;
	gint dns_priority;
	NMSettingConnectionMdns mdns;
	GArray *nameservers;
	GPtrArray *domains;
	GPtrArray *searches;
	GPtrArray *dns_options;
	GArray *nis;
	char *nis_domain;
	GArray *wins;
	GVariant *address_data_variant;
	GVariant *addresses_variant;
	GVariant *route_data_variant;
	GVariant *routes_variant;
	NMDedupMultiIndex *multi_idx;
	const NMPObject *best_default_route;
	union {
		NMIPConfigDedupMultiIdxType idx_ip4_addresses_;
		NMDedupMultiIdxType idx_ip4_addresses;
	};
	union {
		NMIPConfigDedupMultiIdxType idx_ip4_routes_;
		NMDedupMultiIdxType idx_ip4_routes;
	};
} NMIP4ConfigPrivate;

struct _NMIP4Config {
	NMDBusObject parent;
	NMIP4ConfigPrivate _priv;
};

struct _NMIP4ConfigClass {
	NMDBusObjectClass parent;
};

G_DEFINE_TYPE (NMIP4Config, nm_ip4_config, NM_TYPE_DBUS_OBJECT)

#define NM_IP4_CONFIG_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMIP4Config, NM_IS_IP4_CONFIG)

/*****************************************************************************/

static void _add_address (NMIP4Config *self, const NMPObject *obj_new, const NMPlatformIP4Address *new);
static void _add_route (NMIP4Config *self, const NMPObject *obj_new, const NMPlatformIP4Route *new, const NMPObject **out_obj_new);
static const NMDedupMultiEntry *_lookup_route (const NMIP4Config *self,
                                               const NMPObject *needle,
                                               NMPlatformIPRouteCmpType cmp_type);

/*****************************************************************************/

int
nm_ip4_config_get_ifindex (const NMIP4Config *self)
{
	return NM_IP4_CONFIG_GET_PRIVATE (self)->ifindex;
}

NMDedupMultiIndex *
nm_ip4_config_get_multi_idx (const NMIP4Config *self)
{
	return NM_IP4_CONFIG_GET_PRIVATE (self)->multi_idx;
}

/*****************************************************************************/

static gboolean
_ipv4_is_zeronet (in_addr_t network)
{
	/* Same as ipv4_is_zeronet() from kernel's include/linux/in.h. */
	return (network & htonl(0xff000000)) == htonl(0x00000000);
}

/*****************************************************************************/

const NMDedupMultiHeadEntry *
nm_ip4_config_lookup_addresses (const NMIP4Config *self)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return nm_dedup_multi_index_lookup_head (priv->multi_idx,
	                                         &priv->idx_ip4_addresses,
	                                         NULL);
}

void
nm_ip_config_iter_ip4_address_init (NMDedupMultiIter *ipconf_iter, const NMIP4Config *self)
{
	g_return_if_fail (NM_IS_IP4_CONFIG (self));
	nm_dedup_multi_iter_init (ipconf_iter, nm_ip4_config_lookup_addresses (self));
}

/*****************************************************************************/

const NMDedupMultiHeadEntry *
nm_ip4_config_lookup_routes (const NMIP4Config *self)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return nm_dedup_multi_index_lookup_head (priv->multi_idx,
	                                         &priv->idx_ip4_routes,
	                                         NULL);
}

void
nm_ip_config_iter_ip4_route_init (NMDedupMultiIter *ipconf_iter, const NMIP4Config *self)
{
	g_return_if_fail (NM_IS_IP4_CONFIG (self));
	nm_dedup_multi_iter_init (ipconf_iter, nm_ip4_config_lookup_routes (self));
}

/*****************************************************************************/

const NMPObject *
_nm_ip_config_best_default_route_find_better (const NMPObject *obj_cur, const NMPObject *obj_cmp)
{
	int addr_family;
	int c;
	guint metric_cur, metric_cmp;

	nm_assert (   !obj_cur
	           || NM_IN_SET (NMP_OBJECT_GET_TYPE (obj_cur), NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE));
	nm_assert (   !obj_cmp
	           || (   !obj_cur
	               && NM_IN_SET (NMP_OBJECT_GET_TYPE (obj_cmp), NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE))
	           || NMP_OBJECT_GET_TYPE (obj_cur) == NMP_OBJECT_GET_TYPE (obj_cmp));
	nm_assert (   !obj_cur
	           || nm_ip_config_best_default_route_is (obj_cur));

	/* assumes that @obj_cur is already the best default route (or NULL). It checks whether
	 * @obj_cmp is also a default route and returns the best of both. */
	if (   obj_cmp
	    && nm_ip_config_best_default_route_is (obj_cmp)) {
		if (!obj_cur)
			return obj_cmp;

		addr_family = NMP_OBJECT_GET_CLASS (obj_cmp)->addr_family;
		metric_cur = nm_utils_ip_route_metric_normalize (addr_family, NMP_OBJECT_CAST_IP_ROUTE (obj_cur)->metric);
		metric_cmp = nm_utils_ip_route_metric_normalize (addr_family, NMP_OBJECT_CAST_IP_ROUTE (obj_cmp)->metric);

		if (metric_cmp < metric_cur)
			return obj_cmp;

		if (metric_cmp == metric_cur) {
			/* Routes have the same metric. We still want to deterministically
			 * prefer one or the other. It's important to consistently choose one
			 * or the other, so that the order doesn't matter how routes are added
			 * (and merged). */
			c = nmp_object_cmp (obj_cur, obj_cmp);
			if (c != 0)
				return c < 0 ? obj_cur : obj_cmp;

			/* as last resort, compare pointers. */
			if (obj_cmp < obj_cur)
				return obj_cmp;
		}
	}
	return obj_cur;
}

gboolean
_nm_ip_config_best_default_route_set (const NMPObject **best_default_route, const NMPObject *new_candidate)
{
	if (new_candidate == *best_default_route)
		return FALSE;
	nmp_object_ref (new_candidate);
	nm_clear_nmp_object (best_default_route);
	*best_default_route = new_candidate;
	return TRUE;
}

gboolean
_nm_ip_config_best_default_route_merge (const NMPObject **best_default_route, const NMPObject *new_candidate)
{
	new_candidate = _nm_ip_config_best_default_route_find_better (*best_default_route,
	                                                              new_candidate);
	return _nm_ip_config_best_default_route_set (best_default_route, new_candidate);
}

const NMPObject *
nm_ip4_config_best_default_route_get (const NMIP4Config *self)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (self), NULL);

	return NM_IP4_CONFIG_GET_PRIVATE (self)->best_default_route;
}

const NMPObject *
_nm_ip4_config_best_default_route_find (const NMIP4Config *self)
{
	NMDedupMultiIter ipconf_iter;
	const NMPObject *new_best_default_route = NULL;

	nm_ip_config_iter_ip4_route_for_each (&ipconf_iter, self, NULL) {
		new_best_default_route = _nm_ip_config_best_default_route_find_better (new_best_default_route,
		                                                                       ipconf_iter.current->obj);
	}
	return new_best_default_route;
}

in_addr_t
nmtst_ip4_config_get_gateway (NMIP4Config *config)
{
	const NMPObject *rt;

	g_assert (NM_IS_IP4_CONFIG (config));

	rt = nm_ip4_config_best_default_route_get (config);
	if (!rt)
		return 0;
	return NMP_OBJECT_CAST_IP4_ROUTE (rt)->gateway;
}

/*****************************************************************************/

static void
_notify_addresses (NMIP4Config *self)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	nm_clear_g_variant (&priv->address_data_variant);
	nm_clear_g_variant (&priv->addresses_variant);
	_notify (self, PROP_ADDRESS_DATA);
	_notify (self, PROP_ADDRESSES);
}

static void
_notify_routes (NMIP4Config *self)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	nm_assert (priv->best_default_route == _nm_ip4_config_best_default_route_find (self));
	nm_clear_g_variant (&priv->route_data_variant);
	nm_clear_g_variant (&priv->routes_variant);
	_notify (self, PROP_ROUTE_DATA);
	_notify (self, PROP_ROUTES);
}

/*****************************************************************************/

static gint
_addresses_sort_cmp_get_prio (in_addr_t addr)
{
	if (nm_utils_ip4_address_is_link_local (addr))
		return 0;
	return 1;
}

static int
_addresses_sort_cmp (gconstpointer a, gconstpointer b, gpointer user_data)
{
	gint p1, p2;
	const NMPlatformIP4Address *a1 = NMP_OBJECT_CAST_IP4_ADDRESS (*((const NMPObject **) a));
	const NMPlatformIP4Address *a2 = NMP_OBJECT_CAST_IP4_ADDRESS (*((const NMPObject **) b));
	guint32 n1, n2;

	/* Sort by address type. For example link local will
	 * be sorted *after* a global address. */
	p1 = _addresses_sort_cmp_get_prio (a1->address);
	p2 = _addresses_sort_cmp_get_prio (a2->address);
	if (p1 != p2)
		return p1 > p2 ? -1 : 1;

	/* Sort the addresses based on their source. */
	if (a1->addr_source != a2->addr_source)
		return a1->addr_source > a2->addr_source ? -1 : 1;

	if ((a1->label[0] == '\0') != (a2->label[0] == '\0'))
		return (a1->label[0] == '\0') ? -1 : 1;

	/* Finally, sort addresses lexically. We compare only the
	 * network part so that the order of addresses in the same
	 * subnet (and thus also the primary/secondary role) is
	 * preserved.
	 */
	n1 = a1->address & _nm_utils_ip4_prefix_to_netmask (a1->plen);
	n2 = a2->address & _nm_utils_ip4_prefix_to_netmask (a2->plen);

	return memcmp (&n1, &n2, sizeof (guint32));
}

/*****************************************************************************/

static int
sort_captured_addresses (const CList *lst_a, const CList *lst_b, gconstpointer user_data)
{
	const NMPlatformIP4Address *addr_a = NMP_OBJECT_CAST_IP4_ADDRESS (c_list_entry (lst_a, NMDedupMultiEntry, lst_entries)->obj);
	const NMPlatformIP4Address *addr_b = NMP_OBJECT_CAST_IP4_ADDRESS (c_list_entry (lst_b, NMDedupMultiEntry, lst_entries)->obj);

	/* Primary addresses first */
	return NM_FLAGS_HAS (addr_a->n_ifa_flags, IFA_F_SECONDARY) -
	       NM_FLAGS_HAS (addr_b->n_ifa_flags, IFA_F_SECONDARY);
}

NMIP4Config *
nm_ip4_config_clone (const NMIP4Config *self)
{
	NMIP4Config *copy;

	copy = nm_ip4_config_new (nm_ip4_config_get_multi_idx (self), -1);
	nm_ip4_config_replace (copy, self, NULL);

	return copy;
}

NMIP4Config *
nm_ip4_config_capture (NMDedupMultiIndex *multi_idx, NMPlatform *platform, int ifindex)
{
	NMIP4Config *self;
	NMIP4ConfigPrivate *priv;
	const NMDedupMultiHeadEntry *head_entry;
	NMDedupMultiIter iter;
	const NMPObject *plobj = NULL;

	nm_assert (ifindex > 0);

	/* Slaves have no IP configuration */
	if (nm_platform_link_get_master (platform, ifindex) > 0)
		return NULL;

	self = nm_ip4_config_new (multi_idx, ifindex);
	priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	head_entry = nm_platform_lookup_object (platform,
	                                        NMP_OBJECT_TYPE_IP4_ADDRESS,
	                                        ifindex);
	if (head_entry) {
		nmp_cache_iter_for_each (&iter, head_entry, &plobj) {
			if (!_nm_ip_config_add_obj (priv->multi_idx,
			                            &priv->idx_ip4_addresses_,
			                            ifindex,
			                            plobj,
			                            NULL,
			                            FALSE,
			                            TRUE,
			                            NULL,
			                            NULL))
				nm_assert_not_reached ();
		}
		head_entry = nm_ip4_config_lookup_addresses (self);
		nm_assert (head_entry);
		nm_dedup_multi_head_entry_sort (head_entry,
		                                sort_captured_addresses,
		                                NULL);
		_notify_addresses (self);
	}

	head_entry = nm_platform_lookup_object (platform,
	                                        NMP_OBJECT_TYPE_IP4_ROUTE,
	                                        ifindex);

	/* Extract gateway from default route */
	nmp_cache_iter_for_each (&iter, head_entry, &plobj)
		_add_route (self, plobj, NULL, NULL);

	return self;
}

void
nm_ip4_config_add_dependent_routes (NMIP4Config *self,
                                    guint32 route_table,
                                    guint32 route_metric,
                                    GPtrArray **out_ip4_dev_route_blacklist)
{
	GPtrArray *ip4_dev_route_blacklist = NULL;
	const NMPlatformIP4Address *my_addr;
	const NMPlatformIP4Route *my_route;
	int ifindex;
	NMDedupMultiIter iter;

	g_return_if_fail (NM_IS_IP4_CONFIG (self));

	ifindex = nm_ip4_config_get_ifindex (self);
	g_return_if_fail (ifindex > 0);

	/* For IPv6 slaac, we explicitly add the device-routes (onlink) to NMIP6Config.
	 * As we don't do that for IPv4 (and manual IPv6 addresses), add them explicitly. */

	nm_ip_config_iter_ip4_address_for_each (&iter, self, &my_addr) {
		nm_auto_nmpobj NMPObject *r = NULL;
		NMPlatformIP4Route *route;
		in_addr_t network;

		if (my_addr->plen == 0)
			continue;

		nm_assert (my_addr->plen <= 32);

		/* The destination network depends on the peer-address. */
		network = nm_utils_ip4_address_clear_host_address (my_addr->peer_address, my_addr->plen);

		if (_ipv4_is_zeronet (network)) {
			/* Kernel doesn't add device-routes for destinations that
			 * start with 0.x.y.z. Skip them. */
			continue;
		}

		r = nmp_object_new (NMP_OBJECT_TYPE_IP4_ROUTE, NULL);
		route = NMP_OBJECT_CAST_IP4_ROUTE (r);

		route->ifindex = ifindex;
		route->rt_source = NM_IP_CONFIG_SOURCE_KERNEL;
		route->network = network;
		route->plen = my_addr->plen;
		route->pref_src = my_addr->address;
		route->table_coerced = nm_platform_route_table_coerce (route_table);
		route->metric = route_metric;
		route->scope_inv = nm_platform_route_scope_inv (NM_RT_SCOPE_LINK);

		nm_platform_ip_route_normalize (AF_INET, (NMPlatformIPRoute *) route);

		if (_lookup_route (self,
		                   r,
		                   NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID)) {
			/* we already track this route. Don't add it again. */
		} else
			_add_route (self, r, NULL, NULL);

		if (   out_ip4_dev_route_blacklist
		    && (   route_table != RT_TABLE_MAIN
		        || route_metric != NM_PLATFORM_ROUTE_METRIC_IP4_DEVICE_ROUTE)) {
			nm_auto_nmpobj NMPObject *r_dev = NULL;

			r_dev = nmp_object_clone (r, FALSE);
			route = NMP_OBJECT_CAST_IP4_ROUTE (r_dev);
			route->table_coerced = nm_platform_route_table_coerce (RT_TABLE_MAIN);
			route->metric = NM_PLATFORM_ROUTE_METRIC_IP4_DEVICE_ROUTE;

			nm_platform_ip_route_normalize (AF_INET, (NMPlatformIPRoute *) route);

			if (_lookup_route (self,
			                   r_dev,
			                   NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID)) {
				/* we track such a route explicitly. Don't blacklist it. */
			} else {
				if (!ip4_dev_route_blacklist)
					ip4_dev_route_blacklist = g_ptr_array_new_with_free_func ((GDestroyNotify) nmp_object_unref);

				g_ptr_array_add (ip4_dev_route_blacklist,
				                 g_steal_pointer (&r_dev));
			}
		}
	}

again:
	nm_ip_config_iter_ip4_route_for_each (&iter, self, &my_route) {
		NMPlatformIP4Route rt;

		if (   !NM_PLATFORM_IP_ROUTE_IS_DEFAULT (my_route)
		    || my_route->gateway == 0
		    || NM_IS_IP_CONFIG_SOURCE_RTPROT (my_route->rt_source)
		    || nm_ip4_config_get_direct_route_for_host (self,
		                                                my_route->gateway,
		                                                nm_platform_route_table_uncoerce (my_route->table_coerced, TRUE)))
			continue;

		rt = *my_route;
		rt.network = my_route->gateway;
		rt.plen = 32;
		rt.gateway = 0;
		_add_route (self, NULL, &rt, NULL);
		/* adding the route might have invalidated the iteration. Start again. */
		goto again;
	}

	NM_SET_OUT (out_ip4_dev_route_blacklist, ip4_dev_route_blacklist);
}

gboolean
nm_ip4_config_commit (const NMIP4Config *self,
                      NMPlatform *platform,
                      NMIPRouteTableSyncMode route_table_sync)
{
	gs_unref_ptrarray GPtrArray *addresses = NULL;
	gs_unref_ptrarray GPtrArray *routes = NULL;
	gs_unref_ptrarray GPtrArray *routes_prune = NULL;
	int ifindex;
	gboolean success = TRUE;

	g_return_val_if_fail (NM_IS_IP4_CONFIG (self), FALSE);

	ifindex = nm_ip4_config_get_ifindex (self);
	g_return_val_if_fail (ifindex > 0, FALSE);

	addresses = nm_dedup_multi_objs_to_ptr_array_head (nm_ip4_config_lookup_addresses (self),
	                                                   NULL, NULL);

	routes = nm_dedup_multi_objs_to_ptr_array_head (nm_ip4_config_lookup_routes (self),
	                                                NULL, NULL);

	routes_prune = nm_platform_ip_route_get_prune_list (platform,
	                                                    AF_INET,
	                                                    ifindex,
	                                                    route_table_sync);

	nm_platform_ip4_address_sync (platform, ifindex, addresses);

	if (!nm_platform_ip_route_sync (platform,
	                                AF_INET,
	                                ifindex,
	                                routes,
	                                routes_prune,
	                                NULL))
		success = FALSE;

	return success;
}

void
_nm_ip_config_merge_route_attributes (int addr_family,
                                      NMIPRoute *s_route,
                                      NMPlatformIPRoute *r,
                                      guint32 route_table)
{
	GVariant *variant;
	guint32 table;
	NMIPAddr addr;
	NMPlatformIP4Route *r4 = (NMPlatformIP4Route *) r;
	NMPlatformIP6Route *r6 = (NMPlatformIP6Route *) r;
	gboolean onlink;

	nm_assert (s_route);
	nm_assert_addr_family (addr_family);
	nm_assert (r);

#define GET_ATTR(name, dst, variant_type, type, dflt) \
	G_STMT_START { \
		GVariant *_variant = nm_ip_route_get_attribute (s_route, ""name""); \
		\
		if (   _variant \
		    && g_variant_is_of_type (_variant, G_VARIANT_TYPE_ ## variant_type)) \
			(dst) = g_variant_get_ ## type (_variant); \
		else \
			(dst) = (dflt); \
	} G_STMT_END

	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_TABLE, table, UINT32, uint32, 0);
	r->table_coerced = nm_platform_route_table_coerce (table ?: (route_table ?: RT_TABLE_MAIN));

	if (addr_family == AF_INET) {
		GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_TOS,        r4->tos,           BYTE,     byte, 0);
		GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_ONLINK,     onlink,            BOOLEAN,  boolean, FALSE);
	} else
		onlink = FALSE;

	r->r_rtm_flags = 0;
	if (onlink)
		r->r_rtm_flags = RTNH_F_ONLINK;

	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_WINDOW,         r->window,         UINT32,   uint32, 0);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_CWND,           r->cwnd,           UINT32,   uint32, 0);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_INITCWND,       r->initcwnd,       UINT32,   uint32, 0);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_INITRWND,       r->initrwnd,       UINT32,   uint32, 0);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_MTU,            r->mtu,            UINT32,   uint32, 0);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_LOCK_WINDOW,    r->lock_window,    BOOLEAN,  boolean, FALSE);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_LOCK_CWND,      r->lock_cwnd,      BOOLEAN,  boolean, FALSE);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_LOCK_INITCWND,  r->lock_initcwnd,  BOOLEAN,  boolean, FALSE);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_LOCK_INITRWND,  r->lock_initrwnd,  BOOLEAN,  boolean, FALSE);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_LOCK_MTU,       r->lock_mtu,       BOOLEAN,  boolean, FALSE);

	if (   (variant = nm_ip_route_get_attribute (s_route, NM_IP_ROUTE_ATTRIBUTE_SRC))
	    && g_variant_is_of_type (variant, G_VARIANT_TYPE_STRING)) {
		if (inet_pton (addr_family, g_variant_get_string (variant, NULL), &addr) == 1) {
			if (addr_family == AF_INET)
				r4->pref_src = addr.addr4;
			else
				r6->pref_src = addr.addr6;
		}
	}

	if (   addr_family == AF_INET6
	    && (variant = nm_ip_route_get_attribute (s_route, NM_IP_ROUTE_ATTRIBUTE_FROM))
	    && g_variant_is_of_type (variant, G_VARIANT_TYPE_STRING)) {
		gs_free char *string = NULL;
		guint8 plen = 128;
		char *sep;

		string = g_variant_dup_string (variant, NULL);
		sep = strchr (string, '/');
		if (sep) {
			*sep = 0;
			plen = _nm_utils_ascii_str_to_int64 (sep + 1, 10, 1, 128, 255);
		}
		if (   plen <= 128
		    && inet_pton (AF_INET6, string, &addr) == 1) {
			r6->src = addr.addr6;
			r6->src_plen = plen;
		}
	}
#undef GET_ATTR
}

void
nm_ip4_config_merge_setting (NMIP4Config *self,
                             NMSettingIPConfig *setting,
                             NMSettingConnectionMdns mdns,
                             guint32 route_table,
                             guint32 route_metric)
{
	guint naddresses, nroutes, nnameservers, nsearches;
	int i, priority;
	const char *gateway_str;
	guint32 gateway_bin;

	if (!setting)
		return;

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	g_object_freeze_notify (G_OBJECT (self));

	naddresses = nm_setting_ip_config_get_num_addresses (setting);
	nroutes = nm_setting_ip_config_get_num_routes (setting);
	nnameservers = nm_setting_ip_config_get_num_dns (setting);
	nsearches = nm_setting_ip_config_get_num_dns_searches (setting);

	/* Gateway */
	if (   !nm_setting_ip_config_get_never_default (setting)
	    && (gateway_str = nm_setting_ip_config_get_gateway (setting))
	    && inet_pton (AF_INET, gateway_str, &gateway_bin) == 1
	    && gateway_bin) {
		const NMPlatformIP4Route r = {
			.rt_source = NM_IP_CONFIG_SOURCE_USER,
			.gateway = gateway_bin,
			.table_coerced = nm_platform_route_table_coerce (route_table),
			.metric = route_metric,
		};

		_add_route (self, NULL, &r, NULL);
	}

	/* Addresses */
	for (i = 0; i < naddresses; i++) {
		NMIPAddress *s_addr = nm_setting_ip_config_get_address (setting, i);
		GVariant *label;
		NMPlatformIP4Address address;

		memset (&address, 0, sizeof (address));
		nm_ip_address_get_address_binary (s_addr, &address.address);
		address.peer_address = address.address;
		address.plen = nm_ip_address_get_prefix (s_addr);
		nm_assert (address.plen <= 32);
		address.lifetime = NM_PLATFORM_LIFETIME_PERMANENT;
		address.preferred = NM_PLATFORM_LIFETIME_PERMANENT;
		address.addr_source = NM_IP_CONFIG_SOURCE_USER;

		label = nm_ip_address_get_attribute (s_addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
		if (label)
			g_strlcpy (address.label, g_variant_get_string (label, NULL), sizeof (address.label));

		_add_address (self, NULL, &address);
	}

	/* Routes */
	for (i = 0; i < nroutes; i++) {
		NMIPRoute *s_route = nm_setting_ip_config_get_route (setting, i);
		NMPlatformIP4Route route;

		if (nm_ip_route_get_family (s_route) != AF_INET) {
			nm_assert_not_reached ();
			continue;
		}

		memset (&route, 0, sizeof (route));
		nm_ip_route_get_dest_binary (s_route, &route.network);

		route.plen = nm_ip_route_get_prefix (s_route);
		nm_assert (route.plen <= 32);
		if (route.plen == 0)
			continue;

		nm_ip_route_get_next_hop_binary (s_route, &route.gateway);
		if (nm_ip_route_get_metric (s_route) == -1)
			route.metric = route_metric;
		else
			route.metric = nm_ip_route_get_metric (s_route);
		route.rt_source = NM_IP_CONFIG_SOURCE_USER;

		route.network = nm_utils_ip4_address_clear_host_address (route.network, route.plen);

		_nm_ip_config_merge_route_attributes (AF_INET,
		                                      s_route,
		                                      NM_PLATFORM_IP_ROUTE_CAST (&route),
		                                      route_table);
		_add_route (self, NULL, &route, NULL);
	}

	/* DNS */
	if (nm_setting_ip_config_get_ignore_auto_dns (setting)) {
		nm_ip4_config_reset_nameservers (self);
		nm_ip4_config_reset_domains (self);
		nm_ip4_config_reset_searches (self);
	}
	for (i = 0; i < nnameservers; i++) {
		guint32 ip;

		if (inet_pton (AF_INET, nm_setting_ip_config_get_dns (setting, i), &ip) == 1)
			nm_ip4_config_add_nameserver (self, ip);
	}
	for (i = 0; i < nsearches; i++)
		nm_ip4_config_add_search (self, nm_setting_ip_config_get_dns_search (setting, i));

	i = 0;
	while ((i = nm_setting_ip_config_next_valid_dns_option (setting, i)) >= 0) {
		nm_ip4_config_add_dns_option (self, nm_setting_ip_config_get_dns_option (setting, i));
		i++;
	}

	priority = nm_setting_ip_config_get_dns_priority (setting);
	if (priority)
		nm_ip4_config_set_dns_priority (self, priority);

	nm_ip4_config_mdns_set (self, mdns);

	g_object_thaw_notify (G_OBJECT (self));
}

NMSetting *
nm_ip4_config_create_setting (const NMIP4Config *self)
{
	const NMIP4ConfigPrivate *priv;
	NMSettingIPConfig *s_ip4;
	guint nnameservers, nsearches, noptions;
	const char *method = NULL;
	int i;
	NMDedupMultiIter ipconf_iter;
	const NMPlatformIP4Address *address;
	const NMPlatformIP4Route *route;

	s_ip4 = NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());

	if (!self) {
		g_object_set (s_ip4,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
		              NULL);
		return NM_SETTING (s_ip4);
	}

	priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	nnameservers = nm_ip4_config_get_num_nameservers (self);
	nsearches = nm_ip4_config_get_num_searches (self);
	noptions = nm_ip4_config_get_num_dns_options (self);

	/* Addresses */
	nm_ip_config_iter_ip4_address_for_each (&ipconf_iter, self, &address) {
		NMIPAddress *s_addr;

		/* Detect dynamic address */
		if (address->lifetime != NM_PLATFORM_LIFETIME_PERMANENT) {
			method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;
			continue;
		}

		/* Static address found. */
		if (!method)
			method = NM_SETTING_IP4_CONFIG_METHOD_MANUAL;

		s_addr = nm_ip_address_new_binary (AF_INET, &address->address, address->plen, NULL);
		if (*address->label)
			nm_ip_address_set_attribute (s_addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL, g_variant_new_string (address->label));

		nm_setting_ip_config_add_address (s_ip4, s_addr);
		nm_ip_address_unref (s_addr);
	}

	/* Gateway */
	if (   priv->best_default_route
	    && nm_setting_ip_config_get_num_addresses (s_ip4) > 0) {
		g_object_set (s_ip4,
		              NM_SETTING_IP_CONFIG_GATEWAY,
		              nm_utils_inet4_ntop (NMP_OBJECT_CAST_IP4_ROUTE (priv->best_default_route)->gateway,
		                                   NULL),
		              NULL);
	}

	/* Use 'disabled' if the method wasn't previously set */
	if (!method)
		method = NM_SETTING_IP4_CONFIG_METHOD_DISABLED;

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, method,
	              NULL);

	/* Routes */
	nm_ip_config_iter_ip4_route_for_each (&ipconf_iter, self, &route) {
		NMIPRoute *s_route;

		if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT (route))
			continue;

		/* Ignore routes provided by external sources */
		if (route->rt_source != nmp_utils_ip_config_source_round_trip_rtprot (NM_IP_CONFIG_SOURCE_USER))
			continue;

		s_route = nm_ip_route_new_binary (AF_INET,
		                                  &route->network, route->plen,
		                                  &route->gateway, route->metric,
		                                  NULL);
		nm_setting_ip_config_add_route (s_ip4, s_route);
		nm_ip_route_unref (s_route);
	}

	/* DNS */
	for (i = 0; i < nnameservers; i++) {
		guint32 nameserver = nm_ip4_config_get_nameserver (self, i);

		nm_setting_ip_config_add_dns (s_ip4, nm_utils_inet4_ntop (nameserver, NULL));
	}
	for (i = 0; i < nsearches; i++) {
		const char *search = nm_ip4_config_get_search (self, i);

		nm_setting_ip_config_add_dns_search (s_ip4, search);
	}

	for (i = 0; i < noptions; i++) {
		const char *option = nm_ip4_config_get_dns_option (self, i);

		nm_setting_ip_config_add_dns_option (s_ip4, option);
	}

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_DNS_PRIORITY,
	              nm_ip4_config_get_dns_priority (self),
	              NULL);

	return NM_SETTING (s_ip4);
}

/*****************************************************************************/

void
nm_ip4_config_merge (NMIP4Config *dst,
                     const NMIP4Config *src,
                     NMIPConfigMergeFlags merge_flags,
                     guint32 default_route_metric_penalty)
{
	NMIP4ConfigPrivate *dst_priv;
	const NMIP4ConfigPrivate *src_priv;
	guint32 i;
	NMDedupMultiIter ipconf_iter;
	const NMPlatformIP4Address *address = NULL;

	g_return_if_fail (src != NULL);
	g_return_if_fail (dst != NULL);

	dst_priv = NM_IP4_CONFIG_GET_PRIVATE (dst);
	src_priv = NM_IP4_CONFIG_GET_PRIVATE (src);

	g_object_freeze_notify (G_OBJECT (dst));

	/* addresses */
	nm_ip_config_iter_ip4_address_for_each (&ipconf_iter, src, &address)
		_add_address (dst, NMP_OBJECT_UP_CAST (address), NULL);

	/* nameservers */
	if (!NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_DNS)) {
		for (i = 0; i < nm_ip4_config_get_num_nameservers (src); i++)
			nm_ip4_config_add_nameserver (dst, nm_ip4_config_get_nameserver (src, i));
	}

	/* routes */
	if (!NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_ROUTES)) {
		const NMPlatformIP4Route *r_src;

		nm_ip_config_iter_ip4_route_for_each (&ipconf_iter, src, &r_src) {
			if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT (r_src)) {
				if (NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_DEFAULT_ROUTES))
					continue;
				if (default_route_metric_penalty) {
					NMPlatformIP4Route r = *r_src;

					r.metric = nm_utils_ip_route_metric_penalize (AF_INET, r.metric, default_route_metric_penalty);
					_add_route (dst, NULL, &r, NULL);
					continue;
				}
			}
			_add_route (dst, ipconf_iter.current->obj, NULL, NULL);
		}
	}

	/* domains */
	if (!NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_DNS)) {
		for (i = 0; i < nm_ip4_config_get_num_domains (src); i++)
			nm_ip4_config_add_domain (dst, nm_ip4_config_get_domain (src, i));
	}

	/* dns searches */
	if (!NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_DNS)) {
		for (i = 0; i < nm_ip4_config_get_num_searches (src); i++)
			nm_ip4_config_add_search (dst, nm_ip4_config_get_search (src, i));
	}

	/* dns options */
	if (!NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_DNS)) {
		for (i = 0; i < nm_ip4_config_get_num_dns_options (src); i++)
			nm_ip4_config_add_dns_option (dst, nm_ip4_config_get_dns_option (src, i));
	}

	/* MTU */
	if (   src_priv->mtu_source > dst_priv->mtu_source
	    || (   src_priv->mtu_source == dst_priv->mtu_source
	        && (   (!dst_priv->mtu && src_priv->mtu)
	            || (dst_priv->mtu && src_priv->mtu < dst_priv->mtu))))
		nm_ip4_config_set_mtu (dst, src_priv->mtu, src_priv->mtu_source);

	/* NIS */
	if (!NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_DNS)) {
		for (i = 0; i < nm_ip4_config_get_num_nis_servers (src); i++)
			nm_ip4_config_add_nis_server (dst, nm_ip4_config_get_nis_server (src, i));

		if (nm_ip4_config_get_nis_domain (src))
			nm_ip4_config_set_nis_domain (dst, nm_ip4_config_get_nis_domain (src));
	}

	/* WINS */
	if (!NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_DNS)) {
		for (i = 0; i < nm_ip4_config_get_num_wins (src); i++)
			nm_ip4_config_add_wins (dst, nm_ip4_config_get_wins (src, i));
	}

	/* metered flag */
	nm_ip4_config_set_metered (dst, nm_ip4_config_get_metered (dst) ||
	                                nm_ip4_config_get_metered (src));

	/* DNS priority */
	if (nm_ip4_config_get_dns_priority (src))
		nm_ip4_config_set_dns_priority (dst, nm_ip4_config_get_dns_priority (src));

	/* mdns */
	nm_ip4_config_mdns_set (dst,
	                        NM_MAX (nm_ip4_config_mdns_get (src),
	                                nm_ip4_config_mdns_get (dst)));

	g_object_thaw_notify (G_OBJECT (dst));
}

/*****************************************************************************/

static int
_nameservers_get_index (const NMIP4Config *self, guint32 ns)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->nameservers->len; i++) {
		guint32 n = g_array_index (priv->nameservers, guint32, i);

		if (ns == n)
			return (int) i;
	}
	return -1;
}

static int
_domains_get_index (const NMIP4Config *self, const char *domain)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->domains->len; i++) {
		const char *d = g_ptr_array_index (priv->domains, i);

		if (g_strcmp0 (domain, d) == 0)
			return (int) i;
	}
	return -1;
}

static int
_searches_get_index (const NMIP4Config *self, const char *search)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->searches->len; i++) {
		const char *s = g_ptr_array_index (priv->searches, i);

		if (g_strcmp0 (search, s) == 0)
			return (int) i;
	}
	return -1;
}

static int
_dns_options_get_index (const NMIP4Config *self, const char *option)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->dns_options->len; i++) {
		const char *s = g_ptr_array_index (priv->dns_options, i);

		if (g_strcmp0 (option, s) == 0)
			return (int) i;
	}
	return -1;
}

static int
_nis_servers_get_index (const NMIP4Config *self, guint32 nis_server)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->nis->len; i++) {
		guint32 n = g_array_index (priv->nis, guint32, i);

		if (n == nis_server)
			return (int) i;
	}
	return -1;
}

static int
_wins_get_index (const NMIP4Config *self, guint32 wins_server)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->wins->len; i++) {
		guint32 n = g_array_index (priv->wins, guint32, i);

		if (n == wins_server)
			return (int) i;
	}
	return -1;
}

/*****************************************************************************/

/**
 * nm_ip4_config_subtract:
 * @dst: config from which to remove everything in @src
 * @src: config to remove from @dst
 * @default_route_metric_penalty: pretend that on source we applied
 *   a route penalty on the default-route. It means, for default routes
 *   we don't remove routes that match exactly, but those with a lower
 *   metric (with the penalty removed).
 *
 * Removes everything in @src from @dst.
 */
void
nm_ip4_config_subtract (NMIP4Config *dst,
                        const NMIP4Config *src,
                        guint32 default_route_metric_penalty)
{
	NMIP4ConfigPrivate *dst_priv;
	guint i;
	gint idx;
	const NMPlatformIP4Address *a;
	const NMPlatformIP4Route *r;
	NMDedupMultiIter ipconf_iter;
	gboolean changed;
	gboolean changed_default_route;

	g_return_if_fail (src != NULL);
	g_return_if_fail (dst != NULL);

	dst_priv = NM_IP4_CONFIG_GET_PRIVATE (dst);

	g_object_freeze_notify (G_OBJECT (dst));

	/* addresses */
	changed = FALSE;
	nm_ip_config_iter_ip4_address_for_each (&ipconf_iter, src, &a) {
		if (nm_dedup_multi_index_remove_obj (dst_priv->multi_idx,
		                                     &dst_priv->idx_ip4_addresses,
		                                     NMP_OBJECT_UP_CAST (a),
		                                     NULL))
			changed = TRUE;
	}
	if (changed)
		_notify_addresses (dst);

	/* nameservers */
	for (i = 0; i < nm_ip4_config_get_num_nameservers (src); i++) {
		idx = _nameservers_get_index (dst, nm_ip4_config_get_nameserver (src, i));
		if (idx >= 0)
			nm_ip4_config_del_nameserver (dst, idx);
	}

	/* routes */
	changed = FALSE;
	changed_default_route = FALSE;
	nm_ip_config_iter_ip4_route_for_each (&ipconf_iter, src, &r) {
		const NMPObject *o_src = NMP_OBJECT_UP_CAST (r);
		NMPObject o_lookup_copy;
		const NMPObject *o_lookup;
		nm_auto_nmpobj const NMPObject *obj_old = NULL;

		if (   NM_PLATFORM_IP_ROUTE_IS_DEFAULT (r)
		    && default_route_metric_penalty) {
			NMPlatformIP4Route *rr;

			/* the default route was penalized when merging it to the combined ip-config.
			 * When subtracting the routes, we must re-do that process when comparing
			 * the routes. */
			o_lookup = nmp_object_stackinit_obj (&o_lookup_copy, o_src);
			rr = NMP_OBJECT_CAST_IP4_ROUTE (&o_lookup_copy);
			rr->metric = nm_utils_ip_route_metric_penalize (AF_INET, rr->metric, default_route_metric_penalty);
		} else
			o_lookup = o_src;

		if (nm_dedup_multi_index_remove_obj (dst_priv->multi_idx,
		                                     &dst_priv->idx_ip4_routes,
		                                     o_lookup,
		                                     (gconstpointer *) &obj_old)) {
			if (dst_priv->best_default_route == obj_old) {
				nm_clear_nmp_object (&dst_priv->best_default_route);
				changed_default_route = TRUE;
			}
			changed = TRUE;
		}
	}
	if (changed_default_route) {
		_nm_ip_config_best_default_route_set (&dst_priv->best_default_route,
		                                      _nm_ip4_config_best_default_route_find (dst));
		_notify (dst, PROP_GATEWAY);
	}
	if (changed)
		_notify_routes (dst);

	/* domains */
	for (i = 0; i < nm_ip4_config_get_num_domains (src); i++) {
		idx = _domains_get_index (dst, nm_ip4_config_get_domain (src, i));
		if (idx >= 0)
			nm_ip4_config_del_domain (dst, idx);
	}

	/* dns searches */
	for (i = 0; i < nm_ip4_config_get_num_searches (src); i++) {
		idx = _searches_get_index (dst, nm_ip4_config_get_search (src, i));
		if (idx >= 0)
			nm_ip4_config_del_search (dst, idx);
	}

	/* dns options */
	for (i = 0; i < nm_ip4_config_get_num_dns_options (src); i++) {
		idx = _dns_options_get_index (dst, nm_ip4_config_get_dns_option (src, i));
		if (idx >= 0)
			nm_ip4_config_del_dns_option (dst, idx);
	}

	/* MTU */
	if (   nm_ip4_config_get_mtu (src) == nm_ip4_config_get_mtu (dst)
	    && nm_ip4_config_get_mtu_source (src) == nm_ip4_config_get_mtu_source (dst))
		nm_ip4_config_set_mtu (dst, 0, NM_IP_CONFIG_SOURCE_UNKNOWN);

	/* NIS */
	for (i = 0; i < nm_ip4_config_get_num_nis_servers (src); i++) {
		idx = _nis_servers_get_index (dst, nm_ip4_config_get_nis_server (src, i));
		if (idx >= 0)
			nm_ip4_config_del_nis_server (dst, idx);
	}

	if (g_strcmp0 (nm_ip4_config_get_nis_domain (src), nm_ip4_config_get_nis_domain (dst)) == 0)
		nm_ip4_config_set_nis_domain (dst, NULL);

	/* WINS */
	for (i = 0; i < nm_ip4_config_get_num_wins (src); i++) {
		idx = _wins_get_index (dst, nm_ip4_config_get_wins (src, i));
		if (idx >= 0)
			nm_ip4_config_del_wins (dst, idx);
	}

	/* DNS priority */
	if (nm_ip4_config_get_dns_priority (src) == nm_ip4_config_get_dns_priority (dst))
		nm_ip4_config_set_dns_priority (dst, 0);

	/* mdns */
	if (nm_ip4_config_mdns_get (src) == nm_ip4_config_mdns_get (dst))
		nm_ip4_config_mdns_set (dst, NM_SETTING_CONNECTION_MDNS_DEFAULT);

	g_object_thaw_notify (G_OBJECT (dst));
}

static gboolean
_nm_ip4_config_intersect_helper (NMIP4Config *dst,
                                 const NMIP4Config *src,
                                 guint32 default_route_metric_penalty,
                                 gboolean update_dst)
{
	NMIP4ConfigPrivate *dst_priv;
	const NMIP4ConfigPrivate *src_priv;
	NMDedupMultiIter ipconf_iter;
	const NMPlatformIP4Address *a;
	const NMPlatformIP4Route *r;
	const NMPObject *new_best_default_route;
	gboolean changed, result = FALSE;

	g_return_val_if_fail (src, FALSE);
	g_return_val_if_fail (dst, FALSE);

	dst_priv = NM_IP4_CONFIG_GET_PRIVATE (dst);
	src_priv = NM_IP4_CONFIG_GET_PRIVATE (src);

	if (update_dst)
		g_object_freeze_notify (G_OBJECT (dst));

	/* addresses */
	changed = FALSE;
	nm_ip_config_iter_ip4_address_for_each (&ipconf_iter, dst, &a) {
		if (nm_dedup_multi_index_lookup_obj (src_priv->multi_idx,
		                                     &src_priv->idx_ip4_addresses,
		                                     NMP_OBJECT_UP_CAST (a)))
			continue;

		if (!update_dst)
			return TRUE;

		if (nm_dedup_multi_index_remove_entry (dst_priv->multi_idx,
		                                       ipconf_iter.current) != 1)
			nm_assert_not_reached ();
		changed = TRUE;
	}
	if (changed) {
		_notify_addresses (dst);
		result = TRUE;
	}

	/* ignore nameservers */

	/* routes */
	changed = FALSE;
	new_best_default_route = NULL;
	nm_ip_config_iter_ip4_route_for_each (&ipconf_iter, dst, &r) {
		const NMPObject *o_dst = NMP_OBJECT_UP_CAST (r);
		const NMPObject *o_lookup;
		NMPObject o_lookup_copy;

		if (   NM_PLATFORM_IP_ROUTE_IS_DEFAULT (r)
		    && default_route_metric_penalty) {
			NMPlatformIP4Route *rr;

			/* the default route was penalized when merging it to the combined ip-config.
			 * When intersecting the routes, we must re-do that process when comparing
			 * the routes. */
			o_lookup = nmp_object_stackinit_obj (&o_lookup_copy, o_dst);
			rr = NMP_OBJECT_CAST_IP4_ROUTE (&o_lookup_copy);
			rr->metric = nm_utils_ip_route_metric_penalize (AF_INET, rr->metric, default_route_metric_penalty);
		} else
			o_lookup = o_dst;

		if (nm_dedup_multi_index_lookup_obj (src_priv->multi_idx,
		                                     &src_priv->idx_ip4_routes,
		                                     o_lookup)) {
			new_best_default_route = _nm_ip_config_best_default_route_find_better (new_best_default_route, o_dst);
			continue;
		}

		if (!update_dst)
			return TRUE;

		if (nm_dedup_multi_index_remove_entry (dst_priv->multi_idx,
		                                       ipconf_iter.current) != 1)
			nm_assert_not_reached ();
		changed = TRUE;
	}
	if (_nm_ip_config_best_default_route_set (&dst_priv->best_default_route, new_best_default_route)) {
		nm_assert (changed);
		_notify (dst, PROP_GATEWAY);
	}

	if (changed) {
		_notify_routes (dst);
		result = TRUE;
	}

	/* ignore domains */
	/* ignore dns searches */
	/* ignore dns options */
	/* ignore NIS */
	/* ignore WINS */
	/* ignore mdns */

	if (update_dst)
		g_object_thaw_notify (G_OBJECT (dst));
	return result;
}

/**
 * nm_ip4_config_intersect:
 * @dst: a configuration to be updated
 * @src: another configuration
 * @default_route_metric_penalty: the default route metric penalty
 *
 * Computes the intersection between @src and @dst and updates @dst in place
 * with the result.
 */
void
nm_ip4_config_intersect (NMIP4Config *dst,
                         const NMIP4Config *src,
                         guint32 default_route_metric_penalty)
{
	_nm_ip4_config_intersect_helper (dst, src, default_route_metric_penalty, TRUE);
}

/**
 * nm_ip4_config_intersect_alloc:
 * @a: a configuration
 * @b: another configuration
 * @default_route_metric_penalty: the default route metric penalty
 *
 * Computes the intersection between @a and @b and returns the result in a newly
 * allocated configuration.  As a special case, if @a and @b are identical (with
 * respect to the only properties considered - addresses and routes) the
 * functions returns NULL so that one of existing configuration can be reused
 * without allocation.
 *
 * Returns: the intersection between @a and @b, or %NULL if the result is equal
 * to @a and @b.
 */
NMIP4Config *
nm_ip4_config_intersect_alloc (const NMIP4Config *a,
                               const NMIP4Config *b,
                               guint32 default_route_metric_penalty)
{
	NMIP4Config *a_copy;

	if (_nm_ip4_config_intersect_helper ((NMIP4Config *) a, b,
	                                     default_route_metric_penalty, FALSE)) {
		a_copy = nm_ip4_config_clone (a);
		_nm_ip4_config_intersect_helper (a_copy, b, default_route_metric_penalty, TRUE);
		return a_copy;
	} else
		return NULL;
}

/**
 * nm_ip4_config_replace:
 * @dst: config to replace with @src content
 * @src: source config to copy
 * @relevant_changes: return whether there are changes to the
 * destination object that are relevant. This is equal to
 * nm_ip4_config_equal() showing any difference.
 *
 * Replaces everything in @dst with @src so that the two configurations
 * contain the same content -- with the exception of the dbus path.
 *
 * Returns: whether the @dst instance changed in any way (including minor changes,
 * that are not signaled by the output parameter @relevant_changes).
 */
gboolean
nm_ip4_config_replace (NMIP4Config *dst, const NMIP4Config *src, gboolean *relevant_changes)
{
#if NM_MORE_ASSERTS
	gboolean config_equal;
#endif
	gboolean has_minor_changes = FALSE, has_relevant_changes = FALSE, are_equal;
	guint i, num;
	NMIP4ConfigPrivate *dst_priv;
	const NMIP4ConfigPrivate *src_priv;
	NMDedupMultiIter ipconf_iter_src, ipconf_iter_dst;
	const NMDedupMultiHeadEntry *head_entry_src;
	const NMPObject *new_best_default_route;

	g_return_val_if_fail (src != NULL, FALSE);
	g_return_val_if_fail (dst != NULL, FALSE);
	g_return_val_if_fail (src != dst, FALSE);

#if NM_MORE_ASSERTS
	config_equal = nm_ip4_config_equal (dst, src);
#endif

	dst_priv = NM_IP4_CONFIG_GET_PRIVATE (dst);
	src_priv = NM_IP4_CONFIG_GET_PRIVATE (src);

	g_object_freeze_notify (G_OBJECT (dst));

	/* ifindex */
	if (src_priv->ifindex != dst_priv->ifindex) {
		dst_priv->ifindex = src_priv->ifindex;
		has_minor_changes = TRUE;
	}

	/* addresses */
	head_entry_src = nm_ip4_config_lookup_addresses (src);
	nm_dedup_multi_iter_init (&ipconf_iter_src, head_entry_src);
	nm_ip_config_iter_ip4_address_init (&ipconf_iter_dst, dst);
	are_equal = TRUE;
	while (TRUE) {
		gboolean has;
		const NMPlatformIP4Address *r_src = NULL;
		const NMPlatformIP4Address *r_dst = NULL;

		has = nm_ip_config_iter_ip4_address_next (&ipconf_iter_src, &r_src);
		if (has != nm_ip_config_iter_ip4_address_next (&ipconf_iter_dst, &r_dst)) {
			are_equal = FALSE;
			has_relevant_changes = TRUE;
			break;
		}
		if (!has)
			break;

		if (nm_platform_ip4_address_cmp (r_src, r_dst) != 0) {
			are_equal = FALSE;
			if (   r_src->address != r_dst->address
			    || r_src->plen != r_dst->plen
			    || r_src->peer_address != r_dst->peer_address) {
				has_relevant_changes = TRUE;
				break;
			}
		}
	}
	if (!are_equal) {
		has_minor_changes = TRUE;
		nm_dedup_multi_index_dirty_set_idx (dst_priv->multi_idx, &dst_priv->idx_ip4_addresses);
		nm_dedup_multi_iter_for_each (&ipconf_iter_src, head_entry_src) {
			_nm_ip_config_add_obj (dst_priv->multi_idx,
			                       &dst_priv->idx_ip4_addresses_,
			                       dst_priv->ifindex,
			                       ipconf_iter_src.current->obj,
			                       NULL,
			                       FALSE,
			                       TRUE,
			                       NULL,
			                       NULL);
		}
		nm_dedup_multi_index_dirty_remove_idx (dst_priv->multi_idx, &dst_priv->idx_ip4_addresses, FALSE);
		_notify_addresses (dst);
	}

	/* routes */
	head_entry_src = nm_ip4_config_lookup_routes (src);
	nm_dedup_multi_iter_init (&ipconf_iter_src, head_entry_src);
	nm_ip_config_iter_ip4_route_init (&ipconf_iter_dst, dst);
	are_equal = TRUE;
	while (TRUE) {
		gboolean has;
		const NMPlatformIP4Route *r_src = NULL;
		const NMPlatformIP4Route *r_dst = NULL;

		has = nm_ip_config_iter_ip4_route_next (&ipconf_iter_src, &r_src);
		if (has != nm_ip_config_iter_ip4_route_next (&ipconf_iter_dst, &r_dst)) {
			are_equal = FALSE;
			has_relevant_changes = TRUE;
			break;
		}
		if (!has)
			break;

		if (nm_platform_ip4_route_cmp_full (r_src, r_dst) != 0) {
			are_equal = FALSE;
			if (   r_src->plen != r_dst->plen
			    || !nm_utils_ip4_address_same_prefix (r_src->network, r_dst->network, r_src->plen)
			    || r_src->gateway != r_dst->gateway
			    || r_src->metric != r_dst->metric) {
				has_relevant_changes = TRUE;
				break;
			}
		}
	}
	if (!are_equal) {
		has_minor_changes = TRUE;
		new_best_default_route = NULL;
		nm_dedup_multi_index_dirty_set_idx (dst_priv->multi_idx, &dst_priv->idx_ip4_routes);
		nm_dedup_multi_iter_for_each (&ipconf_iter_src, head_entry_src) {
			const NMPObject *o = ipconf_iter_src.current->obj;
			const NMPObject *obj_new;

			_nm_ip_config_add_obj (dst_priv->multi_idx,
			                       &dst_priv->idx_ip4_routes_,
			                       dst_priv->ifindex,
			                       o,
			                       NULL,
			                       FALSE,
			                       TRUE,
			                       NULL,
			                       &obj_new);
			new_best_default_route = _nm_ip_config_best_default_route_find_better (new_best_default_route, obj_new);
		}
		nm_dedup_multi_index_dirty_remove_idx (dst_priv->multi_idx, &dst_priv->idx_ip4_routes, FALSE);
		if (_nm_ip_config_best_default_route_set (&dst_priv->best_default_route, new_best_default_route))
			_notify (dst, PROP_GATEWAY);
		_notify_routes (dst);
	}

	/* nameservers */
	num = nm_ip4_config_get_num_nameservers (src);
	are_equal = num == nm_ip4_config_get_num_nameservers (dst);
	if (are_equal) {
		for (i = 0; i < num; i++ ) {
			if (nm_ip4_config_get_nameserver (src, i) != nm_ip4_config_get_nameserver (dst, i)) {
				are_equal = FALSE;
				break;
			}
		}
	}
	if (!are_equal) {
		nm_ip4_config_reset_nameservers (dst);
		for (i = 0; i < num; i++)
			nm_ip4_config_add_nameserver (dst, nm_ip4_config_get_nameserver (src, i));
		has_relevant_changes = TRUE;
	}

	/* domains */
	num = nm_ip4_config_get_num_domains (src);
	are_equal = num == nm_ip4_config_get_num_domains (dst);
	if (are_equal) {
		for (i = 0; i < num; i++ ) {
			if (g_strcmp0 (nm_ip4_config_get_domain (src, i),
			               nm_ip4_config_get_domain (dst, i))) {
				are_equal = FALSE;
				break;
			}
		}
	}
	if (!are_equal) {
		nm_ip4_config_reset_domains (dst);
		for (i = 0; i < num; i++)
			nm_ip4_config_add_domain (dst, nm_ip4_config_get_domain (src, i));
		has_relevant_changes = TRUE;
	}

	/* dns searches */
	num = nm_ip4_config_get_num_searches (src);
	are_equal = num == nm_ip4_config_get_num_searches (dst);
	if (are_equal) {
		for (i = 0; i < num; i++ ) {
			if (g_strcmp0 (nm_ip4_config_get_search (src, i),
			               nm_ip4_config_get_search (dst, i))) {
				are_equal = FALSE;
				break;
			}
		}
	}
	if (!are_equal) {
		nm_ip4_config_reset_searches (dst);
		for (i = 0; i < num; i++)
			nm_ip4_config_add_search (dst, nm_ip4_config_get_search (src, i));
		has_relevant_changes = TRUE;
	}

	/* dns options */
	num = nm_ip4_config_get_num_dns_options (src);
	are_equal = num == nm_ip4_config_get_num_dns_options (dst);
	if (are_equal) {
		for (i = 0; i < num; i++ ) {
			if (g_strcmp0 (nm_ip4_config_get_dns_option (src, i),
			               nm_ip4_config_get_dns_option (dst, i))) {
				are_equal = FALSE;
				break;
			}
		}
	}
	if (!are_equal) {
		nm_ip4_config_reset_dns_options (dst);
		for (i = 0; i < num; i++)
			nm_ip4_config_add_dns_option (dst, nm_ip4_config_get_dns_option (src, i));
		has_relevant_changes = TRUE;
	}

	dst_priv->mdns = src_priv->mdns;

	/* DNS priority */
	if (src_priv->dns_priority != dst_priv->dns_priority) {
		nm_ip4_config_set_dns_priority (dst, src_priv->dns_priority);
		has_minor_changes = TRUE;
	}

	/* nis */
	num = nm_ip4_config_get_num_nis_servers (src);
	are_equal = num == nm_ip4_config_get_num_nis_servers (dst);
	if (are_equal) {
		for (i = 0; i < num; i++ ) {
			if (nm_ip4_config_get_nis_server (src, i) != nm_ip4_config_get_nis_server (dst, i)) {
				are_equal = FALSE;
				break;
			}
		}
	}
	if (!are_equal) {
		nm_ip4_config_reset_nis_servers (dst);
		for (i = 0; i < num; i++)
			nm_ip4_config_add_nis_server (dst, nm_ip4_config_get_nis_server (src, i));
		has_relevant_changes = TRUE;
	}

	/* nis_domain */
	if (g_strcmp0 (src_priv->nis_domain, dst_priv->nis_domain)) {
		nm_ip4_config_set_nis_domain (dst, src_priv->nis_domain);
		has_relevant_changes = TRUE;
	}

	/* wins */
	num = nm_ip4_config_get_num_wins (src);
	are_equal = num == nm_ip4_config_get_num_wins (dst);
	if (are_equal) {
		for (i = 0; i < num; i++ ) {
			if (nm_ip4_config_get_wins (src, i) != nm_ip4_config_get_wins (dst, i)) {
				are_equal = FALSE;
				break;
			}
		}
	}
	if (!are_equal) {
		nm_ip4_config_reset_wins (dst);
		for (i = 0; i < num; i++)
			nm_ip4_config_add_wins (dst, nm_ip4_config_get_wins (src, i));
		has_relevant_changes = TRUE;
	}

	/* mtu */
	if (   src_priv->mtu != dst_priv->mtu
	    || src_priv->mtu_source != dst_priv->mtu_source) {
		nm_ip4_config_set_mtu (dst, src_priv->mtu, src_priv->mtu_source);
		has_minor_changes = TRUE;
	}

	/* metered */
	if (src_priv->metered != dst_priv->metered) {
		dst_priv->metered = src_priv->metered;
		has_minor_changes = TRUE;
	}

#if NM_MORE_ASSERTS
	/* config_equal does not compare *all* the fields, therefore, we might have has_minor_changes
	 * regardless of config_equal. But config_equal must correspond to has_relevant_changes. */
	nm_assert (config_equal == !has_relevant_changes);
#endif

	g_object_thaw_notify (G_OBJECT (dst));

	if (relevant_changes)
		*relevant_changes = has_relevant_changes;

	return has_relevant_changes || has_minor_changes;
}

void
nm_ip4_config_dump (const NMIP4Config *self, const char *detail)
{
	guint32 tmp;
	guint i;
	const char *str;
	NMDedupMultiIter ipconf_iter;
	const NMPlatformIP4Address *address;
	const NMPlatformIP4Route *route;

	g_message ("--------- NMIP4Config %p (%s)", self, detail);

	if (self == NULL) {
		g_message (" (null)");
		return;
	}

	str = nm_dbus_object_get_path (NM_DBUS_OBJECT (self));
	if (str)
		g_message ("   path: %s", str);

	/* addresses */
	nm_ip_config_iter_ip4_address_for_each (&ipconf_iter, self, &address)
		g_message ("      a: %s", nm_platform_ip4_address_to_string (address, NULL, 0));

	/* nameservers */
	for (i = 0; i < nm_ip4_config_get_num_nameservers (self); i++) {
		tmp = nm_ip4_config_get_nameserver (self, i);
		g_message ("     ns: %s", nm_utils_inet4_ntop (tmp, NULL));
	}

	/* routes */
	nm_ip_config_iter_ip4_route_for_each (&ipconf_iter, self, &route)
		g_message ("     rt: %s", nm_platform_ip4_route_to_string (route, NULL, 0));

	/* domains */
	for (i = 0; i < nm_ip4_config_get_num_domains (self); i++)
		g_message (" domain: %s", nm_ip4_config_get_domain (self, i));

	/* dns searches */
	for (i = 0; i < nm_ip4_config_get_num_searches (self); i++)
		g_message (" search: %s", nm_ip4_config_get_search (self, i));

	/* dns options */
	for (i = 0; i < nm_ip4_config_get_num_dns_options (self); i++)
		g_message (" dnsopt: %s", nm_ip4_config_get_dns_option (self, i));

	g_message (" dnspri: %d", nm_ip4_config_get_dns_priority (self));

	g_message ("    mtu: %"G_GUINT32_FORMAT" (source: %d)", nm_ip4_config_get_mtu (self), (int) nm_ip4_config_get_mtu_source (self));

	/* NIS */
	for (i = 0; i < nm_ip4_config_get_num_nis_servers (self); i++) {
		tmp = nm_ip4_config_get_nis_server (self, i);
		g_message ("    nis: %s", nm_utils_inet4_ntop (tmp, NULL));
	}

	g_message (" nisdmn: %s", nm_ip4_config_get_nis_domain (self) ?: "(none)");

	/* WINS */
	for (i = 0; i < nm_ip4_config_get_num_wins (self); i++) {
		tmp = nm_ip4_config_get_wins (self, i);
		g_message ("   wins: %s", nm_utils_inet4_ntop (tmp, NULL));
	}

	g_message (" mtrd:   %d", (int) nm_ip4_config_get_metered (self));
}

/*****************************************************************************/

void
nm_ip4_config_reset_addresses (NMIP4Config *self)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	if (nm_dedup_multi_index_remove_idx (priv->multi_idx,
	                                     &priv->idx_ip4_addresses) > 0)
		_notify_addresses (self);
}

static void
_add_address (NMIP4Config *self, const NMPObject *obj_new, const NMPlatformIP4Address *new)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	if (_nm_ip_config_add_obj (priv->multi_idx,
	                           &priv->idx_ip4_addresses_,
	                           priv->ifindex,
	                           obj_new,
	                           (const NMPlatformObject *) new,
	                           TRUE,
	                           FALSE,
	                           NULL,
	                           NULL))
		_notify_addresses (self);
}

/**
 * nm_ip4_config_add_address:
 * @self: the #NMIP4Config
 * @new: the new address to add to @self
 *
 * Adds the new address to @self.  If an address with the same basic properties
 * (address, prefix) already exists in @self, it is overwritten with the
 * lifetime and preferred of @new.  The source is also overwritten by the source
 * from @new if that source is higher priority.
 */
void
nm_ip4_config_add_address (NMIP4Config *self, const NMPlatformIP4Address *new)
{
	g_return_if_fail (self);
	g_return_if_fail (new);
	g_return_if_fail (new->plen > 0 && new->plen <= 32);
	g_return_if_fail (NM_IP4_CONFIG_GET_PRIVATE (self)->ifindex > 0);

	_add_address (self, NULL, new);
}

void
_nmtst_ip4_config_del_address (NMIP4Config *self, guint i)
{
	const NMPlatformIP4Address *a;

	a = _nmtst_ip4_config_get_address (self, i);
	if (!nm_ip4_config_nmpobj_remove (self,
	                                  NMP_OBJECT_UP_CAST (a)))
		g_assert_not_reached ();
}

guint
nm_ip4_config_get_num_addresses (const NMIP4Config *self)
{
	const NMDedupMultiHeadEntry *head_entry;

	head_entry = nm_ip4_config_lookup_addresses (self);
	return head_entry ? head_entry->len : 0;
}

const NMPlatformIP4Address *
nm_ip4_config_get_first_address (const NMIP4Config *self)
{
	NMDedupMultiIter iter;
	const NMPlatformIP4Address *a = NULL;

	nm_ip_config_iter_ip4_address_for_each (&iter, self, &a)
		return a;
	return NULL;
}

const NMPlatformIP4Address *
_nmtst_ip4_config_get_address (const NMIP4Config *self, guint i)
{
	NMDedupMultiIter iter;
	const NMPlatformIP4Address *a = NULL;
	guint j;

	j = 0;
	nm_ip_config_iter_ip4_address_for_each (&iter, self, &a) {
		if (i == j)
			return a;
		j++;
	}
	g_return_val_if_reached (NULL);
}

gboolean
nm_ip4_config_address_exists (const NMIP4Config *self,
                              const NMPlatformIP4Address *needle)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	NMPObject obj_stack;

	nmp_object_stackinit_id_ip4_address (&obj_stack,
	                                     priv->ifindex,
	                                     needle->address,
	                                     needle->plen,
	                                     needle->peer_address);
	return !!nm_dedup_multi_index_lookup_obj (priv->multi_idx,
	                                          &priv->idx_ip4_addresses,
	                                          &obj_stack);
}

/*****************************************************************************/

static const NMDedupMultiEntry *
_lookup_route (const NMIP4Config *self,
               const NMPObject *needle,
               NMPlatformIPRouteCmpType cmp_type)
{
	const NMIP4ConfigPrivate *priv;

	nm_assert (NM_IS_IP4_CONFIG (self));
	nm_assert (NMP_OBJECT_GET_TYPE (needle) == NMP_OBJECT_TYPE_IP4_ROUTE);

	priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return _nm_ip_config_lookup_ip_route (priv->multi_idx,
	                                      &priv->idx_ip4_routes_,
	                                      needle,
	                                      cmp_type);
}

void
nm_ip4_config_reset_routes (NMIP4Config *self)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	if (nm_dedup_multi_index_remove_idx (priv->multi_idx,
	                                     &priv->idx_ip4_routes) > 0) {
		if (nm_clear_nmp_object (&priv->best_default_route))
			_notify (self, PROP_GATEWAY);
		_notify_routes (self);
	}
}

static void
_add_route (NMIP4Config *self,
            const NMPObject *obj_new,
            const NMPlatformIP4Route *new,
            const NMPObject **out_obj_new)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	nm_auto_nmpobj const NMPObject *obj_old = NULL;
	const NMPObject *obj_new_2;

	nm_assert ((!new) != (!obj_new));
	nm_assert (!new || _route_valid (new));
	nm_assert (!obj_new || _route_valid (NMP_OBJECT_CAST_IP4_ROUTE (obj_new)));

	if (_nm_ip_config_add_obj (priv->multi_idx,
	                           &priv->idx_ip4_routes_,
	                           priv->ifindex,
	                           obj_new,
	                           (const NMPlatformObject *) new,
	                           TRUE,
	                           FALSE,
	                           &obj_old,
	                           &obj_new_2)) {
		gboolean changed_default_route = FALSE;

		if (   priv->best_default_route == obj_old
		    && obj_old != obj_new_2) {
			changed_default_route = TRUE;
			nm_clear_nmp_object (&priv->best_default_route);
		}
		NM_SET_OUT (out_obj_new, nmp_object_ref (obj_new_2));
		if (_nm_ip_config_best_default_route_merge (&priv->best_default_route, obj_new_2))
			changed_default_route = TRUE;

		if (changed_default_route)
			_notify (self, PROP_GATEWAY);
		_notify_routes (self);
	} else
		NM_SET_OUT (out_obj_new, nmp_object_ref (obj_new_2));
}

/**
 * nm_ip4_config_add_route:
 * @self: the #NMIP4Config
 * @new: the new route to add to @self
 * @out_obj_new: (allow-none): (out): the added route object. Must be unrefed
 *   by caller.
 *
 * Adds the new route to @self.  If a route with the same basic properties
 * (network, prefix) already exists in @self, it is overwritten including the
 * gateway and metric of @new.  The source is also overwritten by the source
 * from @new if that source is higher priority.
 */
void
nm_ip4_config_add_route (NMIP4Config *self,
                         const NMPlatformIP4Route *new,
                         const NMPObject **out_obj_new)
{
	g_return_if_fail (self);
	g_return_if_fail (new);
	g_return_if_fail (new->plen <= 32);
	g_return_if_fail (NM_IP4_CONFIG_GET_PRIVATE (self)->ifindex > 0);

	_add_route (self, NULL, new, out_obj_new);
}

void
_nmtst_ip4_config_del_route (NMIP4Config *self, guint i)
{
	const NMPlatformIP4Route *r;

	r = _nmtst_ip4_config_get_route (self, i);
	if (!nm_ip4_config_nmpobj_remove (self,
	                                  NMP_OBJECT_UP_CAST (r)))
		g_assert_not_reached ();
}

guint
nm_ip4_config_get_num_routes (const NMIP4Config *self)
{
	const NMDedupMultiHeadEntry *head_entry;

	head_entry = nm_ip4_config_lookup_routes (self);
	nm_assert (!head_entry || head_entry->len == c_list_length (&head_entry->lst_entries_head));
	return head_entry ? head_entry->len : 0;
}

const NMPlatformIP4Route *
_nmtst_ip4_config_get_route (const NMIP4Config *self, guint i)
{
	NMDedupMultiIter iter;
	const NMPlatformIP4Route *r = NULL;
	guint j;

	j = 0;
	nm_ip_config_iter_ip4_route_for_each (&iter, self, &r) {
		if (i == j)
			return r;
		j++;
	}
	g_return_val_if_reached (NULL);
}

const NMPlatformIP4Route *
nm_ip4_config_get_direct_route_for_host (const NMIP4Config *self,
                                         in_addr_t host,
                                         guint32 route_table)
{
	const NMPlatformIP4Route *best_route = NULL;
	const NMPlatformIP4Route *item;
	NMDedupMultiIter ipconf_iter;

	g_return_val_if_fail (host, NULL);

	nm_ip_config_iter_ip4_route_for_each (&ipconf_iter, self, &item) {
		if (item->gateway != 0)
			continue;

		if (best_route && best_route->plen > item->plen)
			continue;

		if (nm_platform_route_table_uncoerce (item->table_coerced, TRUE) != route_table)
			continue;

		if (nm_utils_ip4_address_clear_host_address (host, item->plen) != nm_utils_ip4_address_clear_host_address (item->network, item->plen))
			continue;

		if (best_route && best_route->metric <= item->metric)
			continue;

		best_route = item;
	}
	return best_route;
}

/*****************************************************************************/

void
nm_ip4_config_reset_nameservers (NMIP4Config *self)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	if (priv->nameservers->len != 0) {
		g_array_set_size (priv->nameservers, 0);
		_notify (self, PROP_NAMESERVERS);
	}
}

void
nm_ip4_config_add_nameserver (NMIP4Config *self, guint32 new)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	int i;

	g_return_if_fail (new != 0);

	for (i = 0; i < priv->nameservers->len; i++)
		if (new == g_array_index (priv->nameservers, guint32, i))
			return;

	g_array_append_val (priv->nameservers, new);
	_notify (self, PROP_NAMESERVERS);
}

void
nm_ip4_config_del_nameserver (NMIP4Config *self, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	g_return_if_fail (i < priv->nameservers->len);

	g_array_remove_index (priv->nameservers, i);
	_notify (self, PROP_NAMESERVERS);
}

guint
nm_ip4_config_get_num_nameservers (const NMIP4Config *self)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return priv->nameservers->len;
}

guint32
nm_ip4_config_get_nameserver (const NMIP4Config *self, guint i)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return g_array_index (priv->nameservers, guint32, i);
}

const in_addr_t *
_nm_ip4_config_get_nameserver (const NMIP4Config *self, guint i)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return &g_array_index (priv->nameservers, guint32, i);
}

/*****************************************************************************/

gboolean
_nm_ip_config_check_and_add_domain (GPtrArray *array, const char *domain)
{
	char *copy = NULL;
	size_t len;

	g_return_val_if_fail (domain, FALSE);
	g_return_val_if_fail (domain[0] != '\0', FALSE);

	if (domain[0] == '.' || strstr (domain, ".."))
		return FALSE;

	len = strlen (domain);
	if (domain[len - 1] == '.')
		domain = copy = g_strndup (domain, len - 1);

	if (nm_utils_strv_find_first ((char **) array->pdata, array->len, domain) >= 0) {
		g_free (copy);
		return FALSE;
	}

	g_ptr_array_add (array, copy ?: g_strdup (domain));
	return TRUE;
}

void
nm_ip4_config_reset_domains (NMIP4Config *self)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	if (priv->domains->len != 0) {
		g_ptr_array_set_size (priv->domains, 0);
		_notify (self, PROP_DOMAINS);
	}
}

void
nm_ip4_config_add_domain (NMIP4Config *self, const char *domain)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	if (_nm_ip_config_check_and_add_domain (priv->domains, domain))
		_notify (self, PROP_DOMAINS);
}

void
nm_ip4_config_del_domain (NMIP4Config *self, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	g_return_if_fail (i < priv->domains->len);

	g_ptr_array_remove_index (priv->domains, i);
	_notify (self, PROP_DOMAINS);
}

guint
nm_ip4_config_get_num_domains (const NMIP4Config *self)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return priv->domains->len;
}

const char *
nm_ip4_config_get_domain (const NMIP4Config *self, guint i)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return g_ptr_array_index (priv->domains, i);
}

/*****************************************************************************/

void
nm_ip4_config_reset_searches (NMIP4Config *self)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	if (priv->searches->len != 0) {
		g_ptr_array_set_size (priv->searches, 0);
		_notify (self, PROP_SEARCHES);
	}
}

void
nm_ip4_config_add_search (NMIP4Config *self, const char *search)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	if (_nm_ip_config_check_and_add_domain (priv->searches, search))
		_notify (self, PROP_SEARCHES);
}

void
nm_ip4_config_del_search (NMIP4Config *self, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	g_return_if_fail (i < priv->searches->len);

	g_ptr_array_remove_index (priv->searches, i);
	_notify (self, PROP_SEARCHES);
}

guint
nm_ip4_config_get_num_searches (const NMIP4Config *self)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return priv->searches->len;
}

const char *
nm_ip4_config_get_search (const NMIP4Config *self, guint i)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return g_ptr_array_index (priv->searches, i);
}

/*****************************************************************************/

void
nm_ip4_config_reset_dns_options (NMIP4Config *self)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	if (priv->dns_options->len != 0) {
		g_ptr_array_set_size (priv->dns_options, 0);
		_notify (self, PROP_DNS_OPTIONS);
	}
}

void
nm_ip4_config_add_dns_option (NMIP4Config *self, const char *new)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	int i;

	g_return_if_fail (new != NULL);
	g_return_if_fail (new[0] != '\0');

	for (i = 0; i < priv->dns_options->len; i++)
		if (!g_strcmp0 (g_ptr_array_index (priv->dns_options, i), new))
			return;

	g_ptr_array_add (priv->dns_options, g_strdup (new));
	_notify (self, PROP_DNS_OPTIONS);
}

void
nm_ip4_config_del_dns_option(NMIP4Config *self, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	g_return_if_fail (i < priv->dns_options->len);

	g_ptr_array_remove_index (priv->dns_options, i);
	_notify (self, PROP_DNS_OPTIONS);
}

guint
nm_ip4_config_get_num_dns_options (const NMIP4Config *self)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return priv->dns_options->len;
}

const char *
nm_ip4_config_get_dns_option (const NMIP4Config *self, guint i)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return g_ptr_array_index (priv->dns_options, i);
}

/*****************************************************************************/

NMSettingConnectionMdns
nm_ip4_config_mdns_get (const NMIP4Config *self)
{
	return NM_IP4_CONFIG_GET_PRIVATE (self)->mdns;
}

void
nm_ip4_config_mdns_set (NMIP4Config *self,
                        NMSettingConnectionMdns mdns)
{
	NM_IP4_CONFIG_GET_PRIVATE (self)->mdns = mdns;
}

/*****************************************************************************/

void
nm_ip4_config_set_dns_priority (NMIP4Config *self, gint priority)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	if (priority != priv->dns_priority) {
		priv->dns_priority = priority;
		_notify (self, PROP_DNS_PRIORITY);
	}
}

gint
nm_ip4_config_get_dns_priority (const NMIP4Config *self)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return priv->dns_priority;
}

/*****************************************************************************/

void
nm_ip4_config_reset_nis_servers (NMIP4Config *self)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	g_array_set_size (priv->nis, 0);
}

void
nm_ip4_config_add_nis_server (NMIP4Config *self, guint32 nis)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	int i;

	for (i = 0; i < priv->nis->len; i++)
		if (nis == g_array_index (priv->nis, guint32, i))
			return;

	g_array_append_val (priv->nis, nis);
}

void
nm_ip4_config_del_nis_server (NMIP4Config *self, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	g_return_if_fail (i < priv->nis->len);

	g_array_remove_index (priv->nis, i);
}

guint
nm_ip4_config_get_num_nis_servers (const NMIP4Config *self)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return priv->nis->len;
}

guint32
nm_ip4_config_get_nis_server (const NMIP4Config *self, guint i)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return g_array_index (priv->nis, guint32, i);
}

void
nm_ip4_config_set_nis_domain (NMIP4Config *self, const char *domain)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	g_free (priv->nis_domain);
	priv->nis_domain = g_strdup (domain);
}

const char *
nm_ip4_config_get_nis_domain (const NMIP4Config *self)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return priv->nis_domain;
}

/*****************************************************************************/

void
nm_ip4_config_reset_wins (NMIP4Config *self)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	if (priv->wins->len != 0) {
		g_array_set_size (priv->wins, 0);
		_notify (self, PROP_WINS_SERVERS);
	}
}

void
nm_ip4_config_add_wins (NMIP4Config *self, guint32 wins)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	int i;

	g_return_if_fail (wins != 0);

	for (i = 0; i < priv->wins->len; i++)
		if (wins == g_array_index (priv->wins, guint32, i))
			return;

	g_array_append_val (priv->wins, wins);
	_notify (self, PROP_WINS_SERVERS);
}

void
nm_ip4_config_del_wins (NMIP4Config *self, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	g_return_if_fail (i < priv->wins->len);

	g_array_remove_index (priv->wins, i);
	_notify (self, PROP_WINS_SERVERS);
}

guint
nm_ip4_config_get_num_wins (const NMIP4Config *self)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return priv->wins->len;
}

guint32
nm_ip4_config_get_wins (const NMIP4Config *self, guint i)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return g_array_index (priv->wins, guint32, i);
}

/*****************************************************************************/

void
nm_ip4_config_set_mtu (NMIP4Config *self, guint32 mtu, NMIPConfigSource source)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	if (!mtu)
		source = NM_IP_CONFIG_SOURCE_UNKNOWN;

	priv->mtu = mtu;
	priv->mtu_source = source;
}

guint32
nm_ip4_config_get_mtu (const NMIP4Config *self)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return priv->mtu;
}

NMIPConfigSource
nm_ip4_config_get_mtu_source (const NMIP4Config *self)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return priv->mtu_source;
}

/*****************************************************************************/

void
nm_ip4_config_set_metered (NMIP4Config *self, gboolean metered)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	priv->metered = metered;
}

gboolean
nm_ip4_config_get_metered (const NMIP4Config *self)
{
	const NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	return priv->metered;
}

/*****************************************************************************/

const NMPObject *
nm_ip4_config_nmpobj_lookup (const NMIP4Config *self, const NMPObject *needle)
{
	const NMIP4ConfigPrivate *priv;
	const NMDedupMultiIdxType *idx_type;

	g_return_val_if_fail (NM_IS_IP4_CONFIG (self), NULL);

	priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	switch (NMP_OBJECT_GET_TYPE (needle)) {
	case NMP_OBJECT_TYPE_IP4_ADDRESS:
		idx_type = &priv->idx_ip4_addresses;
		break;
	case NMP_OBJECT_TYPE_IP4_ROUTE:
		idx_type = &priv->idx_ip4_routes;
		break;
	default:
		g_return_val_if_reached (NULL);
	}

	return nm_dedup_multi_entry_get_obj (nm_dedup_multi_index_lookup_obj (priv->multi_idx,
	                                                                      idx_type,
	                                                                      needle));
}

gboolean
nm_ip4_config_nmpobj_remove (NMIP4Config *self,
                             const NMPObject *needle)
{
	NMIP4ConfigPrivate *priv;
	NMDedupMultiIdxType *idx_type;
	nm_auto_nmpobj const NMPObject *obj_old = NULL;
	guint n;

	g_return_val_if_fail (NM_IS_IP4_CONFIG (self), FALSE);

	priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	switch (NMP_OBJECT_GET_TYPE (needle)) {
	case NMP_OBJECT_TYPE_IP4_ADDRESS:
		idx_type = &priv->idx_ip4_addresses;
		break;
	case NMP_OBJECT_TYPE_IP4_ROUTE:
		idx_type = &priv->idx_ip4_routes;
		break;
	default:
		g_return_val_if_reached (FALSE);
	}

	n = nm_dedup_multi_index_remove_obj (priv->multi_idx,
	                                     idx_type,
	                                     needle,
	                                     (gconstpointer *) &obj_old);
	if (n != 1) {
		nm_assert (n == 0);
		return FALSE;
	}

	nm_assert (NMP_OBJECT_GET_TYPE (obj_old) == NMP_OBJECT_GET_TYPE (needle));

	switch (NMP_OBJECT_GET_TYPE (obj_old)) {
	case NMP_OBJECT_TYPE_IP4_ADDRESS:
		_notify_addresses (self);
		break;
	case NMP_OBJECT_TYPE_IP4_ROUTE:
		if (priv->best_default_route == obj_old) {
			if (_nm_ip_config_best_default_route_set (&priv->best_default_route,
			                                          _nm_ip4_config_best_default_route_find (self)))
				_notify (self, PROP_GATEWAY);
		}
		_notify_routes (self);
		break;
	default:
		nm_assert_not_reached ();
	}
	return TRUE;
}

/*****************************************************************************/

static inline void
hash_u32 (GChecksum *sum, guint32 n)
{
	g_checksum_update (sum, (const guint8 *) &n, sizeof (n));
}

void
nm_ip4_config_hash (const NMIP4Config *self, GChecksum *sum, gboolean dns_only)
{
	guint i;
	const char *s;
	NMDedupMultiIter ipconf_iter;
	const NMPlatformIP4Address *address;
	const NMPlatformIP4Route *route;

	g_return_if_fail (self);
	g_return_if_fail (sum);

	if (!dns_only) {
		nm_ip_config_iter_ip4_address_for_each (&ipconf_iter, self, &address) {
			hash_u32 (sum, address->address);
			hash_u32 (sum, address->plen);
			hash_u32 (sum, address->peer_address & _nm_utils_ip4_prefix_to_netmask (address->plen));
		}

		nm_ip_config_iter_ip4_route_for_each (&ipconf_iter, self, &route) {
			hash_u32 (sum, route->network);
			hash_u32 (sum, route->plen);
			hash_u32 (sum, route->gateway);
			hash_u32 (sum, route->metric);
		}

		for (i = 0; i < nm_ip4_config_get_num_nis_servers (self); i++)
			hash_u32 (sum, nm_ip4_config_get_nis_server (self, i));

		s = nm_ip4_config_get_nis_domain (self);
		if (s)
			g_checksum_update (sum, (const guint8 *) s, strlen (s));
	}

	for (i = 0; i < nm_ip4_config_get_num_nameservers (self); i++)
		hash_u32 (sum, nm_ip4_config_get_nameserver (self, i));

	for (i = 0; i < nm_ip4_config_get_num_wins (self); i++)
		hash_u32 (sum, nm_ip4_config_get_wins (self, i));

	for (i = 0; i < nm_ip4_config_get_num_domains (self); i++) {
		s = nm_ip4_config_get_domain (self, i);
		g_checksum_update (sum, (const guint8 *) s, strlen (s));
	}

	for (i = 0; i < nm_ip4_config_get_num_searches (self); i++) {
		s = nm_ip4_config_get_search (self, i);
		g_checksum_update (sum, (const guint8 *) s, strlen (s));
	}

	for (i = 0; i < nm_ip4_config_get_num_dns_options (self); i++) {
		s = nm_ip4_config_get_dns_option (self, i);
		g_checksum_update (sum, (const guint8 *) s, strlen (s));
	}
}

/**
 * nm_ip4_config_equal:
 * @a: first config to compare
 * @b: second config to compare
 *
 * Compares two #NMIP4Configs for basic equality.  This means that all
 * attributes must exist in the same order in both configs (addresses, routes,
 * domains, DNS servers, etc) but some attributes (address lifetimes, and address
 * and route sources) are ignored.
 *
 * Returns: %TRUE if the configurations are basically equal to each other,
 * %FALSE if not
 */
gboolean
nm_ip4_config_equal (const NMIP4Config *a, const NMIP4Config *b)
{
	GChecksum *a_checksum = g_checksum_new (G_CHECKSUM_SHA1);
	GChecksum *b_checksum = g_checksum_new (G_CHECKSUM_SHA1);
	guchar a_data[20], b_data[20];
	gsize a_len = sizeof (a_data);
	gsize b_len = sizeof (b_data);
	gboolean equal;

	if (a)
		nm_ip4_config_hash (a, a_checksum, FALSE);
	if (b)
		nm_ip4_config_hash (b, b_checksum, FALSE);

	g_checksum_get_digest (a_checksum, a_data, &a_len);
	g_checksum_get_digest (b_checksum, b_data, &b_len);

	nm_assert (a_len == sizeof (a_data));
	nm_assert (b_len == sizeof (b_data));
	equal = !memcmp (a_data, b_data, a_len);

	g_checksum_free (a_checksum);
	g_checksum_free (b_checksum);

	return equal;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMIP4Config *self = NM_IP4_CONFIG (object);
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	const NMDedupMultiHeadEntry *head_entry;
	NMDedupMultiIter ipconf_iter;
	const NMPlatformIP4Route *route;
	GVariantBuilder builder_data, builder_legacy;

	switch (prop_id) {
	case PROP_IFINDEX:
		g_value_set_int (value, priv->ifindex);
		break;
	case PROP_ADDRESS_DATA:
	case PROP_ADDRESSES:
		nm_assert (!!priv->address_data_variant == !!priv->addresses_variant);

		if (priv->address_data_variant)
			goto out_addresses_cached;

		g_variant_builder_init (&builder_data, G_VARIANT_TYPE ("aa{sv}"));
		g_variant_builder_init (&builder_legacy, G_VARIANT_TYPE ("aau"));

		head_entry = nm_ip4_config_lookup_addresses (self);
		if (head_entry) {
			gs_free const NMPObject **addresses = NULL;
			guint naddr, i;

			addresses = (const NMPObject **) nm_dedup_multi_objs_to_array_head (head_entry, NULL, NULL, &naddr);
			nm_assert (addresses && naddr);

			g_qsort_with_data (addresses,
			                   naddr,
			                   sizeof (addresses[0]),
			                   _addresses_sort_cmp,
			                   NULL);

			/* Build address data variant */
			for (i = 0; i < naddr; i++) {
				GVariantBuilder addr_builder;
				const NMPlatformIP4Address *address = NMP_OBJECT_CAST_IP4_ADDRESS (addresses[i]);

				g_variant_builder_init (&addr_builder, G_VARIANT_TYPE ("a{sv}"));
				g_variant_builder_add (&addr_builder, "{sv}",
				                       "address",
				                       g_variant_new_string (nm_utils_inet4_ntop (address->address, NULL)));
				g_variant_builder_add (&addr_builder, "{sv}",
				                       "prefix",
				                       g_variant_new_uint32 (address->plen));
				if (address->peer_address != address->address) {
					g_variant_builder_add (&addr_builder, "{sv}",
					                       "peer",
					                       g_variant_new_string (nm_utils_inet4_ntop (address->peer_address, NULL)));
				}

				if (*address->label) {
					g_variant_builder_add (&addr_builder, "{sv}",
					                       NM_IP_ADDRESS_ATTRIBUTE_LABEL,
					                       g_variant_new_string (address->label));
				}

				g_variant_builder_add (&builder_data, "a{sv}", &addr_builder);

				{
					const guint32 dbus_addr[3] = {
					    address->address,
					    address->plen,
					    (   i == 0
					     && priv->best_default_route)
					       ? NMP_OBJECT_CAST_IP4_ROUTE (priv->best_default_route)->gateway
					       : (guint32) 0,
					};

					g_variant_builder_add (&builder_legacy, "@au",
					                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
					                                                  dbus_addr, 3, sizeof (guint32)));
				}
			}
		}

		priv->address_data_variant = g_variant_ref_sink (g_variant_builder_end (&builder_data));
		priv->addresses_variant = g_variant_ref_sink (g_variant_builder_end (&builder_legacy));

out_addresses_cached:
		g_value_set_variant (value,
		                     prop_id == PROP_ADDRESS_DATA ?
		                     priv->address_data_variant :
		                     priv->addresses_variant);
		break;
	case PROP_ROUTE_DATA:
	case PROP_ROUTES:
		nm_assert (!!priv->route_data_variant == !!priv->routes_variant);

		if (priv->route_data_variant)
			goto out_routes_cached;

		g_variant_builder_init (&builder_data, G_VARIANT_TYPE ("aa{sv}"));
		g_variant_builder_init (&builder_legacy, G_VARIANT_TYPE ("aau"));

		nm_ip_config_iter_ip4_route_for_each (&ipconf_iter, self, &route) {
			GVariantBuilder route_builder;

			nm_assert (_route_valid (route));

			g_variant_builder_init (&route_builder, G_VARIANT_TYPE ("a{sv}"));
			g_variant_builder_add (&route_builder, "{sv}",
			                       "dest",
			                       g_variant_new_string (nm_utils_inet4_ntop (route->network, NULL)));
			g_variant_builder_add (&route_builder, "{sv}",
			                       "prefix",
			                       g_variant_new_uint32 (route->plen));
			if (route->gateway) {
				g_variant_builder_add (&route_builder, "{sv}",
				                       "next-hop",
				                       g_variant_new_string (nm_utils_inet4_ntop (route->gateway, NULL)));
			}
			g_variant_builder_add (&route_builder, "{sv}",
			                       "metric",
			                       g_variant_new_uint32 (route->metric));

			if (!nm_platform_route_table_is_main (route->table_coerced)) {
				g_variant_builder_add (&route_builder, "{sv}",
				                       "table",
				                       g_variant_new_uint32 (nm_platform_route_table_uncoerce (route->table_coerced, TRUE)));
			}

			g_variant_builder_add (&builder_data, "a{sv}", &route_builder);

			/* legacy versions of nm_ip4_route_set_prefix() in libnm-util assert that the
			 * plen is positive. Skip the default routes not to break older clients. */
			if (   nm_platform_route_table_is_main (route->table_coerced)
			    && !NM_PLATFORM_IP_ROUTE_IS_DEFAULT (route)) {
				const guint32 dbus_route[4] = {
				    route->network,
				    route->plen,
				    route->gateway,
				    route->metric,
				};

				g_variant_builder_add (&builder_legacy, "@au",
				                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
				                                                  dbus_route, 4, sizeof (guint32)));
			}
		}

		priv->route_data_variant = g_variant_ref_sink (g_variant_builder_end (&builder_data));
		priv->routes_variant = g_variant_ref_sink (g_variant_builder_end (&builder_legacy));

out_routes_cached:
		g_value_set_variant (value,
		                     prop_id == PROP_ROUTE_DATA ?
		                     priv->route_data_variant :
		                     priv->routes_variant);
		break;
	case PROP_GATEWAY:
		if (priv->best_default_route) {
			g_value_set_string (value,
			                    nm_utils_inet4_ntop (NMP_OBJECT_CAST_IP4_ROUTE (priv->best_default_route)->gateway,
			                                         NULL));
		} else
			g_value_set_string (value, NULL);
		break;
	case PROP_NAMESERVERS:
		g_value_take_variant (value,
		                      g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
		                                                 priv->nameservers->data,
		                                                 priv->nameservers->len,
		                                                 sizeof (guint32)));
		break;
	case PROP_DOMAINS:
		nm_utils_g_value_set_strv (value, priv->domains);
		break;
	case PROP_SEARCHES:
		nm_utils_g_value_set_strv (value, priv->searches);
		break;
	case PROP_DNS_OPTIONS:
		nm_utils_g_value_set_strv (value, priv->dns_options);
		break;
	case PROP_DNS_PRIORITY:
		g_value_set_int (value, priv->dns_priority);
		break;
	case PROP_WINS_SERVERS:
		g_value_take_variant (value,
		                      g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
		                                                 priv->wins->data,
		                                                 priv->wins->len,
		                                                 sizeof (guint32)));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
	NMIP4Config *self = NM_IP4_CONFIG (object);
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_MULTI_IDX:
		/* construct-only */
		priv->multi_idx = g_value_get_pointer (value);
		if (!priv->multi_idx)
			g_return_if_reached ();
		nm_dedup_multi_index_ref (priv->multi_idx);
		break;
	case PROP_IFINDEX:
		/* construct-only */
		priv->ifindex = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_ip4_config_init (NMIP4Config *self)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	nm_ip_config_dedup_multi_idx_type_init ((NMIPConfigDedupMultiIdxType *) &priv->idx_ip4_addresses,
	                                        NMP_OBJECT_TYPE_IP4_ADDRESS);
	nm_ip_config_dedup_multi_idx_type_init ((NMIPConfigDedupMultiIdxType *) &priv->idx_ip4_routes,
	                                        NMP_OBJECT_TYPE_IP4_ROUTE);

	priv->mdns = NM_SETTING_CONNECTION_MDNS_DEFAULT;
	priv->nameservers = g_array_new (FALSE, FALSE, sizeof (guint32));
	priv->domains = g_ptr_array_new_with_free_func (g_free);
	priv->searches = g_ptr_array_new_with_free_func (g_free);
	priv->dns_options = g_ptr_array_new_with_free_func (g_free);
	priv->nis = g_array_new (FALSE, TRUE, sizeof (guint32));
	priv->wins = g_array_new (FALSE, TRUE, sizeof (guint32));
}

NMIP4Config *
nm_ip4_config_new (NMDedupMultiIndex *multi_idx, int ifindex)
{
	g_return_val_if_fail (ifindex >= -1, NULL);
	return (NMIP4Config *) g_object_new (NM_TYPE_IP4_CONFIG,
	                                     NM_IP4_CONFIG_MULTI_IDX, multi_idx,
	                                     NM_IP4_CONFIG_IFINDEX, ifindex,
	                                     NULL);
}

static void
finalize (GObject *object)
{
	NMIP4Config *self = NM_IP4_CONFIG (object);
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	nm_clear_nmp_object (&priv->best_default_route);

	nm_dedup_multi_index_remove_idx (priv->multi_idx, &priv->idx_ip4_addresses);
	nm_dedup_multi_index_remove_idx (priv->multi_idx, &priv->idx_ip4_routes);

	nm_clear_g_variant (&priv->address_data_variant);
	nm_clear_g_variant (&priv->addresses_variant);
	nm_clear_g_variant (&priv->route_data_variant);
	nm_clear_g_variant (&priv->routes_variant);

	g_array_unref (priv->nameservers);
	g_ptr_array_unref (priv->domains);
	g_ptr_array_unref (priv->searches);
	g_ptr_array_unref (priv->dns_options);
	g_array_unref (priv->nis);
	g_free (priv->nis_domain);
	g_array_unref (priv->wins);

	G_OBJECT_CLASS (nm_ip4_config_parent_class)->finalize (object);

	nm_dedup_multi_index_unref (priv->multi_idx);
}

static const NMDBusInterfaceInfoExtended interface_info_ip4_config = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_IP4_CONFIG,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Addresses",   "aau",    NM_IP4_CONFIG_ADDRESSES),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("AddressData", "aa{sv}", NM_IP4_CONFIG_ADDRESS_DATA),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Gateway",     "s",      NM_IP4_CONFIG_GATEWAY),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Routes",      "aau",    NM_IP4_CONFIG_ROUTES),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("RouteData",   "aa{sv}", NM_IP4_CONFIG_ROUTE_DATA),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Nameservers", "au",     NM_IP4_CONFIG_NAMESERVERS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Domains",     "as",     NM_IP4_CONFIG_DOMAINS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Searches",    "as",     NM_IP4_CONFIG_SEARCHES),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("DnsOptions",  "as",     NM_IP4_CONFIG_DNS_OPTIONS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("DnsPriority", "i",      NM_IP4_CONFIG_DNS_PRIORITY),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("WinsServers", "au",     NM_IP4_CONFIG_WINS_SERVERS),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_ip4_config_class_init (NMIP4ConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (config_class);

	dbus_object_class->export_path = NM_DBUS_EXPORT_PATH_NUMBERED (NM_DBUS_PATH"/IP4Config");
	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_ip4_config);

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize = finalize;

	obj_properties[PROP_MULTI_IDX] =
	    g_param_spec_pointer (NM_IP4_CONFIG_MULTI_IDX, "", "",
	                            G_PARAM_WRITABLE
	                          | G_PARAM_CONSTRUCT_ONLY
	                          | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_IFINDEX] =
	    g_param_spec_int (NM_IP4_CONFIG_IFINDEX, "", "",
	                      -1, G_MAXINT, -1,
	                      G_PARAM_READWRITE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ADDRESS_DATA] =
	    g_param_spec_variant (NM_IP4_CONFIG_ADDRESS_DATA, "", "",
	                          G_VARIANT_TYPE ("aa{sv}"),
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ADDRESSES] =
	    g_param_spec_variant (NM_IP4_CONFIG_ADDRESSES, "", "",
	                          G_VARIANT_TYPE ("aau"),
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ROUTE_DATA] =
	    g_param_spec_variant (NM_IP4_CONFIG_ROUTE_DATA, "", "",
	                          G_VARIANT_TYPE ("aa{sv}"),
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ROUTES] =
	    g_param_spec_variant (NM_IP4_CONFIG_ROUTES, "", "",
	                          G_VARIANT_TYPE ("aau"),
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_GATEWAY] =
	    g_param_spec_string (NM_IP4_CONFIG_GATEWAY, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_NAMESERVERS] =
	    g_param_spec_variant (NM_IP4_CONFIG_NAMESERVERS, "", "",
	                          G_VARIANT_TYPE ("au"),
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DOMAINS] =
	    g_param_spec_boxed (NM_IP4_CONFIG_DOMAINS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_SEARCHES] =
	    g_param_spec_boxed (NM_IP4_CONFIG_SEARCHES, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DNS_OPTIONS] =
	     g_param_spec_boxed (NM_IP4_CONFIG_DNS_OPTIONS, "", "",
	                         G_TYPE_STRV,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DNS_PRIORITY] =
	     g_param_spec_int (NM_IP4_CONFIG_DNS_PRIORITY, "", "",
	                       G_MININT32, G_MAXINT32, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_WINS_SERVERS] =
	    g_param_spec_variant (NM_IP4_CONFIG_WINS_SERVERS, "", "",
	                          G_VARIANT_TYPE ("au"),
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
