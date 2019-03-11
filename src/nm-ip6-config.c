/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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

#include "nm-ip6-config.h"

#include <arpa/inet.h>
#include <resolv.h>
#include <linux/rtnetlink.h>

#include "nm-utils/nm-dedup-multi.h"

#include "nm-utils.h"
#include "platform/nmp-object.h"
#include "platform/nm-platform.h"
#include "platform/nm-platform-utils.h"
#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"
#include "nm-ip4-config.h"
#include "ndisc/nm-ndisc.h"
#include "nm-dbus-object.h"

/*****************************************************************************/

static gboolean
_route_valid (const NMPlatformIP6Route *r)
{
	struct in6_addr n;

	return    r
	       && r->plen <= 128
	       && (memcmp (&r->network,
	                   nm_utils_ip6_address_clear_host_address (&n, &r->network, r->plen),
	                   sizeof (n)) == 0);
}

/*****************************************************************************/

typedef struct {
	int ifindex;
	int dns_priority;
	NMSettingIP6ConfigPrivacy privacy;
	GArray *nameservers;
	GPtrArray *domains;
	GPtrArray *searches;
	GPtrArray *dns_options;
	GVariant *address_data_variant;
	GVariant *addresses_variant;
	GVariant *route_data_variant;
	GVariant *routes_variant;
	NMDedupMultiIndex *multi_idx;
	const NMPObject *best_default_route;
	union {
		NMIPConfigDedupMultiIdxType idx_ip6_addresses_;
		NMDedupMultiIdxType idx_ip6_addresses;
	};
	union {
		NMIPConfigDedupMultiIdxType idx_ip6_routes_;
		NMDedupMultiIdxType idx_ip6_routes;
	};
} NMIP6ConfigPrivate;

struct _NMIP6Config {
	NMDBusObject parent;
	NMIP6ConfigPrivate _priv;
};

struct _NMIP6ConfigClass {
	NMDBusObjectClass parent;
};

G_DEFINE_TYPE (NMIP6Config, nm_ip6_config, NM_TYPE_DBUS_OBJECT)

#define NM_IP6_CONFIG_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMIP6Config, NM_IS_IP6_CONFIG)

NM_GOBJECT_PROPERTIES_DEFINE (NMIP6Config,
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
	PROP_DNS_PRIORITY,
);

/*****************************************************************************/

static void _add_address (NMIP6Config *self, const NMPObject *obj_new, const NMPlatformIP6Address *new);
static void _add_route (NMIP6Config *self, const NMPObject *obj_new, const NMPlatformIP6Route *new, const NMPObject **out_obj_new);
static const NMDedupMultiEntry *_lookup_route (const NMIP6Config *self,
                                               const NMPObject *needle,
                                               NMPlatformIPRouteCmpType cmp_type);

/*****************************************************************************/

int
nm_ip6_config_get_ifindex (const NMIP6Config *self)
{
	return NM_IP6_CONFIG_GET_PRIVATE (self)->ifindex;
}

NMDedupMultiIndex *
nm_ip6_config_get_multi_idx (const NMIP6Config *self)
{
	return NM_IP6_CONFIG_GET_PRIVATE (self)->multi_idx;
}

void
nm_ip6_config_set_privacy (NMIP6Config *self, NMSettingIP6ConfigPrivacy privacy)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	priv->privacy = privacy;
}

/*****************************************************************************/

const NMDedupMultiHeadEntry *
nm_ip6_config_lookup_addresses (const NMIP6Config *self)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	return nm_dedup_multi_index_lookup_head (priv->multi_idx,
	                                         &priv->idx_ip6_addresses,
	                                         NULL);
}

void
nm_ip_config_iter_ip6_address_init (NMDedupMultiIter *ipconf_iter, const NMIP6Config *self)
{
	g_return_if_fail (NM_IS_IP6_CONFIG (self));
	nm_dedup_multi_iter_init (ipconf_iter, nm_ip6_config_lookup_addresses (self));
}

/*****************************************************************************/

const NMDedupMultiHeadEntry *
nm_ip6_config_lookup_routes (const NMIP6Config *self)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	return nm_dedup_multi_index_lookup_head (priv->multi_idx,
	                                         &priv->idx_ip6_routes,
	                                         NULL);
}

void
nm_ip_config_iter_ip6_route_init (NMDedupMultiIter *ipconf_iter, const NMIP6Config *self)
{
	g_return_if_fail (NM_IS_IP6_CONFIG (self));
	nm_dedup_multi_iter_init (ipconf_iter, nm_ip6_config_lookup_routes (self));
}

/*****************************************************************************/

const NMPObject *
nm_ip6_config_best_default_route_get (const NMIP6Config *self)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (self), NULL);

	return NM_IP6_CONFIG_GET_PRIVATE (self)->best_default_route;
}

const NMPObject *
_nm_ip6_config_best_default_route_find (const NMIP6Config *self)
{
	NMDedupMultiIter ipconf_iter;
	const NMPObject *new_best_default_route = NULL;

	nm_ip_config_iter_ip6_route_for_each (&ipconf_iter, self, NULL) {
		new_best_default_route = _nm_ip_config_best_default_route_find_better (new_best_default_route,
		                                                                       ipconf_iter.current->obj);
	}
	return new_best_default_route;
}

/*****************************************************************************/

static void
_notify_addresses (NMIP6Config *self)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	nm_clear_g_variant (&priv->address_data_variant);
	nm_clear_g_variant (&priv->addresses_variant);
	nm_gobject_notify_together (self, PROP_ADDRESS_DATA,
	                                  PROP_ADDRESSES);
}

static void
_notify_routes (NMIP6Config *self)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	nm_assert (priv->best_default_route == _nm_ip6_config_best_default_route_find (self));
	nm_clear_g_variant (&priv->route_data_variant);
	nm_clear_g_variant (&priv->routes_variant);
	nm_gobject_notify_together (self, PROP_ROUTE_DATA,
	                                  PROP_ROUTES);
}

/*****************************************************************************/

static int
_addresses_sort_cmp_get_prio (const struct in6_addr *addr)
{
	if (IN6_IS_ADDR_V4MAPPED (addr))
		return 0;
	if (IN6_IS_ADDR_V4COMPAT (addr))
		return 1;
	if (IN6_IS_ADDR_UNSPECIFIED (addr))
		return 2;
	if (IN6_IS_ADDR_LOOPBACK (addr))
		return 3;
	if (IN6_IS_ADDR_LINKLOCAL (addr))
		return 4;
	if (IN6_IS_ADDR_SITELOCAL (addr))
		return 5;
	return 6;
}

static int
_addresses_sort_cmp (const NMPlatformIP6Address *a1,
                     const NMPlatformIP6Address *a2,
                     gboolean prefer_temp)
{
	int p1, p2, c;
	gboolean perm1, perm2, tent1, tent2;
	gboolean ipv6_privacy1, ipv6_privacy2;

	/* tentative addresses are always sorted back... */
	/* sort tentative addresses after non-tentative. */
	tent1 = (a1->n_ifa_flags & IFA_F_TENTATIVE);
	tent2 = (a2->n_ifa_flags & IFA_F_TENTATIVE);
	if (tent1 != tent2)
		return tent1 ? 1 : -1;

	/* Sort by address type. For example link local will
	 * be sorted *after* site local or global. */
	p1 = _addresses_sort_cmp_get_prio (&a1->address);
	p2 = _addresses_sort_cmp_get_prio (&a2->address);
	if (p1 != p2)
		return p1 > p2 ? -1 : 1;

	ipv6_privacy1 = !!(a1->n_ifa_flags & (IFA_F_MANAGETEMPADDR | IFA_F_TEMPORARY));
	ipv6_privacy2 = !!(a2->n_ifa_flags & (IFA_F_MANAGETEMPADDR | IFA_F_TEMPORARY));
	if (ipv6_privacy1 || ipv6_privacy2) {
		gboolean public1 = TRUE, public2 = TRUE;

		if (ipv6_privacy1) {
			if (a1->n_ifa_flags & IFA_F_TEMPORARY)
				public1 = prefer_temp;
			else
				public1 = !prefer_temp;
		}
		if (ipv6_privacy2) {
			if (a2->n_ifa_flags & IFA_F_TEMPORARY)
				public2 = prefer_temp;
			else
				public2 = !prefer_temp;
		}

		if (public1 != public2)
			return public1 ? -1 : 1;
	}

	/* Sort the addresses based on their source. */
	if (a1->addr_source != a2->addr_source)
		return a1->addr_source > a2->addr_source ? -1 : 1;

	/* sort permanent addresses before non-permanent. */
	perm1 = (a1->n_ifa_flags & IFA_F_PERMANENT);
	perm2 = (a2->n_ifa_flags & IFA_F_PERMANENT);
	if (perm1 != perm2)
		return perm1 ? -1 : 1;

	/* finally sort addresses lexically */
	c = memcmp (&a1->address, &a2->address, sizeof (a2->address));
	return c != 0 ? c : memcmp (a1, a2, sizeof (*a1));
}

static int
_addresses_sort_cmp_prop (gconstpointer a, gconstpointer b, gpointer user_data)
{
	return _addresses_sort_cmp (NMP_OBJECT_CAST_IP6_ADDRESS (*((const NMPObject **) a)),
	                            NMP_OBJECT_CAST_IP6_ADDRESS (*((const NMPObject **) b)),
	                            ((NMSettingIP6ConfigPrivacy) GPOINTER_TO_INT (user_data)) == NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR);
}

static int
sort_captured_addresses (const CList *lst_a, const CList *lst_b, gconstpointer user_data)
{
	const NMPlatformIP6Address *addr_a = NMP_OBJECT_CAST_IP6_ADDRESS (c_list_entry (lst_a, NMDedupMultiEntry, lst_entries)->obj);
	const NMPlatformIP6Address *addr_b = NMP_OBJECT_CAST_IP6_ADDRESS (c_list_entry (lst_b, NMDedupMultiEntry, lst_entries)->obj);

	return _addresses_sort_cmp (addr_a, addr_b,
	                            ((NMSettingIP6ConfigPrivacy) GPOINTER_TO_INT (user_data)) == NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR);
}

gboolean
_nmtst_ip6_config_addresses_sort (NMIP6Config *self)
{
	NMIP6ConfigPrivate *priv;
	const NMDedupMultiHeadEntry *head_entry;

	g_return_val_if_fail (NM_IS_IP6_CONFIG (self), FALSE);

	head_entry = nm_ip6_config_lookup_addresses (self);
	if (head_entry && head_entry->len > 1) {
		gboolean changed;
		gs_free gconstpointer *addresses_old = NULL;
		guint naddr, j;
		NMDedupMultiIter iter;

		priv = NM_IP6_CONFIG_GET_PRIVATE (self);

		addresses_old = nm_dedup_multi_objs_to_array_head (head_entry, NULL, NULL, &naddr);
		nm_assert (addresses_old);
		nm_assert (naddr > 0 && naddr == head_entry->len);

		nm_dedup_multi_head_entry_sort (head_entry,
		                                sort_captured_addresses,
		                                GINT_TO_POINTER (priv->privacy));

		changed = FALSE;
		j = 0;
		nm_dedup_multi_iter_for_each (&iter, head_entry) {
			nm_assert (j < naddr);
			if (iter.current->obj != addresses_old[j++])
				changed = TRUE;
		}
		nm_assert (j == naddr);

		if (changed) {
			_notify_addresses (self);
			return TRUE;
		}
	}
	return FALSE;
}

NMIP6Config *
nm_ip6_config_clone (const NMIP6Config *self)
{
	NMIP6Config *copy;

	copy = nm_ip6_config_new (nm_ip6_config_get_multi_idx (self), -1);
	nm_ip6_config_replace (copy, self, NULL);

	return copy;
}

NMIP6Config *
nm_ip6_config_capture (NMDedupMultiIndex *multi_idx, NMPlatform *platform, int ifindex, NMSettingIP6ConfigPrivacy use_temporary)
{
	NMIP6Config *self;
	NMIP6ConfigPrivate *priv;
	const NMDedupMultiHeadEntry *head_entry;
	NMDedupMultiIter iter;
	const NMPObject *plobj = NULL;

	nm_assert (ifindex > 0);

	/* Slaves have no IP configuration */
	if (nm_platform_link_get_master (platform, ifindex) > 0)
		return NULL;

	self = nm_ip6_config_new (multi_idx, ifindex);
	priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	head_entry = nm_platform_lookup_object (platform,
	                                        NMP_OBJECT_TYPE_IP6_ADDRESS,
	                                        ifindex);
	if (head_entry) {
		nmp_cache_iter_for_each (&iter, head_entry, &plobj) {
			if (!_nm_ip_config_add_obj (priv->multi_idx,
			                            &priv->idx_ip6_addresses_,
			                            ifindex,
			                            plobj,
			                            NULL,
			                            FALSE,
			                            TRUE,
			                            NULL,
			                            NULL))
				nm_assert_not_reached ();
		}
		head_entry = nm_ip6_config_lookup_addresses (self);
		nm_assert (head_entry);
		nm_dedup_multi_head_entry_sort (head_entry,
		                                sort_captured_addresses,
		                                GINT_TO_POINTER (use_temporary));
		_notify_addresses (self);
	}

	head_entry = nm_platform_lookup_object (platform,
	                                        NMP_OBJECT_TYPE_IP6_ROUTE,
	                                        ifindex);

	nmp_cache_iter_for_each (&iter, head_entry, &plobj)
		_add_route (self, plobj, NULL, NULL);

	return self;
}

void
nm_ip6_config_update_routes_metric (NMIP6Config *self, gint64 metric)
{
	gs_free NMPlatformIP6Route *routes = NULL;
	gboolean need_update = FALSE;
	const NMPlatformIP6Route *r;
	NMDedupMultiIter iter;
	guint num = 0, i = 0;

	nm_ip_config_iter_ip6_route_for_each (&iter, self, &r) {
		if (r->metric != metric)
			need_update = TRUE;
		num++;
	}
	if (!need_update)
		return;

	routes = g_new (NMPlatformIP6Route, num);
	nm_ip_config_iter_ip6_route_for_each (&iter, self, &r) {
		routes[i] = *r;
		routes[i].metric = metric;
		i++;
	}

	g_object_freeze_notify (G_OBJECT (self));
	nm_ip6_config_reset_routes (self);
	for (i = 0; i < num; i++)
		nm_ip6_config_add_route (self, &routes[i], NULL);
	g_object_thaw_notify (G_OBJECT (self));
}

void
nm_ip6_config_add_dependent_routes (NMIP6Config *self,
                                    guint32 route_table,
                                    guint32 route_metric)
{
	const NMPlatformIP6Address *my_addr;
	const NMPlatformIP6Route *my_route;
	int ifindex;
	NMDedupMultiIter iter;

	g_return_if_fail (NM_IS_IP6_CONFIG (self));

	ifindex = nm_ip6_config_get_ifindex (self);
	g_return_if_fail (ifindex > 0);

	/* For IPv6 addresses received via SLAAC/autoconf, we explicitly add the
	 * device-routes (onlink) to NMIP6Config.
	 *
	 * For manually added IPv6 routes, add the device routes explicitly. */

	nm_ip_config_iter_ip6_address_for_each (&iter, self, &my_addr) {
		NMPlatformIP6Route *route;
		gboolean has_peer;
		int routes_n, routes_i;

		if (NM_FLAGS_HAS (my_addr->n_ifa_flags, IFA_F_NOPREFIXROUTE))
			continue;
		if (my_addr->plen == 0)
			continue;

		has_peer = !IN6_IS_ADDR_UNSPECIFIED (&my_addr->peer_address);

		/* If we have an IPv6 peer, we add two /128 routes
		 * (unless, both addresses are identical). */
		routes_n = (   has_peer
		            && !IN6_ARE_ADDR_EQUAL (&my_addr->address, &my_addr->peer_address))
		           ? 2 : 1;

		for (routes_i = 0; routes_i < routes_n; routes_i++) {
			nm_auto_nmpobj NMPObject *r = NULL;

			r = nmp_object_new (NMP_OBJECT_TYPE_IP6_ROUTE, NULL);
			route = NMP_OBJECT_CAST_IP6_ROUTE (r);

			route->ifindex = ifindex;
			route->rt_source = NM_IP_CONFIG_SOURCE_KERNEL;
			route->table_coerced = nm_platform_route_table_coerce (route_table);
			route->metric = route_metric;

			if (has_peer) {
				if (routes_i == 0)
					route->network = my_addr->address;
				else
					route->network = my_addr->peer_address;
				route->plen = 128;
			} else {
				nm_utils_ip6_address_clear_host_address (&route->network, &my_addr->address, my_addr->plen);
				route->plen = my_addr->plen;
			}

			nm_platform_ip_route_normalize (AF_INET6, (NMPlatformIPRoute *) route);

			if (_lookup_route (self,
			                   r,
			                   NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID)) {
				/* we already track this route. Don't add it again. */
			} else
				_add_route (self, r, NULL, NULL);
		}
	}

again:
	nm_ip_config_iter_ip6_route_for_each (&iter, self, &my_route) {
		NMPlatformIP6Route rt;

		if (   !NM_PLATFORM_IP_ROUTE_IS_DEFAULT (my_route)
		    || IN6_IS_ADDR_UNSPECIFIED (&my_route->gateway)
		    || NM_IS_IP_CONFIG_SOURCE_RTPROT (my_route->rt_source)
		    || nm_ip6_config_get_direct_route_for_host (self,
		                                                &my_route->gateway,
		                                                nm_platform_route_table_uncoerce (my_route->table_coerced, TRUE)))
			continue;

		rt = *my_route;
		rt.network = my_route->gateway;
		rt.plen = 128;
		rt.gateway = in6addr_any;
		_add_route (self, NULL, &rt, NULL);
		/* adding the route might have invalidated the iteration. Start again. */
		goto again;
	}
}

gboolean
nm_ip6_config_commit (const NMIP6Config *self,
                      NMPlatform *platform,
                      NMIPRouteTableSyncMode route_table_sync,
                      GPtrArray **out_temporary_not_available)
{
	gs_unref_ptrarray GPtrArray *addresses = NULL;
	gs_unref_ptrarray GPtrArray *routes = NULL;
	gs_unref_ptrarray GPtrArray *routes_prune = NULL;
	int ifindex;
	gboolean success = TRUE;

	g_return_val_if_fail (NM_IS_IP6_CONFIG (self), FALSE);

	ifindex = nm_ip6_config_get_ifindex (self);
	g_return_val_if_fail (ifindex > 0, FALSE);

	addresses = nm_dedup_multi_objs_to_ptr_array_head (nm_ip6_config_lookup_addresses (self),
	                                                   NULL, NULL);

	routes = nm_dedup_multi_objs_to_ptr_array_head (nm_ip6_config_lookup_routes (self),
	                                                NULL, NULL);

	routes_prune = nm_platform_ip_route_get_prune_list (platform,
	                                                    AF_INET6,
	                                                    ifindex,
	                                                    route_table_sync);

	nm_platform_ip6_address_sync (platform, ifindex, addresses, FALSE);

	if (!nm_platform_ip_route_sync (platform,
	                                AF_INET6,
	                                ifindex,
	                                routes,
	                                routes_prune,
	                                out_temporary_not_available))
		success = FALSE;

	return success;
}

void
nm_ip6_config_merge_setting (NMIP6Config *self,
                             NMSettingIPConfig *setting,
                             guint32 route_table,
                             guint32 route_metric)
{
	guint naddresses, nroutes, nnameservers, nsearches;
	const char *gateway_str;
	struct in6_addr gateway_bin;
	int i, priority;

	if (!setting)
		return;

	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	naddresses = nm_setting_ip_config_get_num_addresses (setting);
	nroutes = nm_setting_ip_config_get_num_routes (setting);
	nnameservers = nm_setting_ip_config_get_num_dns (setting);
	nsearches = nm_setting_ip_config_get_num_dns_searches (setting);

	g_object_freeze_notify (G_OBJECT (self));

	/* Gateway */
	if (   !nm_setting_ip_config_get_never_default (setting)
	    && (gateway_str = nm_setting_ip_config_get_gateway (setting))
	    && inet_pton (AF_INET6, gateway_str, &gateway_bin) == 1
	    && !IN6_IS_ADDR_UNSPECIFIED (&gateway_bin)) {
		const NMPlatformIP6Route r = {
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
		NMPlatformIP6Address address;

		memset (&address, 0, sizeof (address));
		nm_ip_address_get_address_binary (s_addr, &address.address);
		address.plen = nm_ip_address_get_prefix (s_addr);
		nm_assert (address.plen <= 128);
		address.lifetime = NM_PLATFORM_LIFETIME_PERMANENT;
		address.preferred = NM_PLATFORM_LIFETIME_PERMANENT;
		address.addr_source = NM_IP_CONFIG_SOURCE_USER;

		_add_address (self, NULL, &address);
	}

	/* Routes */
	for (i = 0; i < nroutes; i++) {
		NMIPRoute *s_route = nm_setting_ip_config_get_route (setting, i);
		NMPlatformIP6Route route;

		if (nm_ip_route_get_family (s_route) != AF_INET6) {
			nm_assert_not_reached ();
			continue;
		}

		memset (&route, 0, sizeof (route));
		nm_ip_route_get_dest_binary (s_route, &route.network);

		route.plen = nm_ip_route_get_prefix (s_route);
		nm_assert (route.plen <= 128);
		if (route.plen == 0)
			continue;

		nm_ip_route_get_next_hop_binary (s_route, &route.gateway);
		if (nm_ip_route_get_metric (s_route) == -1)
			route.metric = route_metric;
		else
			route.metric = nm_ip_route_get_metric (s_route);
		route.rt_source = NM_IP_CONFIG_SOURCE_USER;

		nm_utils_ip6_address_clear_host_address (&route.network, &route.network, route.plen);

		_nm_ip_config_merge_route_attributes (AF_INET,
		                                      s_route,
		                                      NM_PLATFORM_IP_ROUTE_CAST (&route),
		                                      route_table);
		_add_route (self, NULL, &route, NULL);
	}

	/* DNS */
	if (nm_setting_ip_config_get_ignore_auto_dns (setting)) {
		nm_ip6_config_reset_nameservers (self);
		nm_ip6_config_reset_domains (self);
		nm_ip6_config_reset_searches (self);
	}
	for (i = 0; i < nnameservers; i++) {
		 struct in6_addr ip;

		if (inet_pton (AF_INET6, nm_setting_ip_config_get_dns (setting, i), &ip) == 1)
			nm_ip6_config_add_nameserver (self, &ip);
	}
	for (i = 0; i < nsearches; i++)
		nm_ip6_config_add_search (self, nm_setting_ip_config_get_dns_search (setting, i));

	i = 0;
	while ((i = nm_setting_ip_config_next_valid_dns_option (setting, i)) >= 0) {
		nm_ip6_config_add_dns_option (self, nm_setting_ip_config_get_dns_option (setting, i));
		i++;
	}

	priority = nm_setting_ip_config_get_dns_priority (setting);
	if (priority)
		nm_ip6_config_set_dns_priority (self, priority);

	g_object_thaw_notify (G_OBJECT (self));
}

NMSetting *
nm_ip6_config_create_setting (const NMIP6Config *self)
{
	const NMIP6ConfigPrivate *priv;
	NMSettingIPConfig *s_ip6;
	guint nnameservers, nsearches, noptions;
	const char *method = NULL;
	char sbuf[NM_UTILS_INET_ADDRSTRLEN];
	int i;
	NMDedupMultiIter ipconf_iter;
	const NMPlatformIP6Address *address;
	const NMPlatformIP6Route *route;

	s_ip6 = NM_SETTING_IP_CONFIG (nm_setting_ip6_config_new ());

	if (!self) {
		g_object_set (s_ip6,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
		              NULL);
		return NM_SETTING (s_ip6);
	}

	priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	nnameservers = nm_ip6_config_get_num_nameservers (self);
	nsearches = nm_ip6_config_get_num_searches (self);
	noptions = nm_ip6_config_get_num_dns_options (self);

	/* Addresses */
	nm_ip_config_iter_ip6_address_for_each (&ipconf_iter, self, &address) {
		NMIPAddress *s_addr;

		/* Ignore link-local address. */
		if (IN6_IS_ADDR_LINKLOCAL (&address->address)) {
			if (!method)
				method = NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL;
			continue;
		}

		/* Detect dynamic address */
		if (address->lifetime != NM_PLATFORM_LIFETIME_PERMANENT) {
			method = NM_SETTING_IP6_CONFIG_METHOD_AUTO;
			continue;
		}

		/* Static address found. */
		if (!method || strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL) == 0)
			method = NM_SETTING_IP6_CONFIG_METHOD_MANUAL;

		s_addr = nm_ip_address_new_binary (AF_INET6, &address->address, address->plen, NULL);
		nm_setting_ip_config_add_address (s_ip6, s_addr);
		nm_ip_address_unref (s_addr);
	}

	/* Gateway */
	if (   priv->best_default_route
	    && nm_setting_ip_config_get_num_addresses (s_ip6) > 0) {
		g_object_set (s_ip6,
		              NM_SETTING_IP_CONFIG_GATEWAY,
		              nm_utils_inet6_ntop (&NMP_OBJECT_CAST_IP6_ROUTE (priv->best_default_route)->gateway,
		                                   sbuf),
		              NULL);
	}

	/* Use 'ignore' if the method wasn't previously set */
	if (!method)
		method = NM_SETTING_IP6_CONFIG_METHOD_IGNORE;

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, method,
	              NULL);

	/* Routes */
	nm_ip_config_iter_ip6_route_for_each (&ipconf_iter, self, &route) {
		NMIPRoute *s_route;

		/* Ignore link-local route. */
		if (IN6_IS_ADDR_LINKLOCAL (&route->network))
			continue;

		if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT (route))
			continue;

		/* Ignore routes provided by external sources */
		if (route->rt_source != nmp_utils_ip_config_source_round_trip_rtprot (NM_IP_CONFIG_SOURCE_USER))
			continue;

		s_route = nm_ip_route_new_binary (AF_INET6,
		                                  &route->network, route->plen,
		                                  &route->gateway, route->metric,
		                                  NULL);
		nm_setting_ip_config_add_route (s_ip6, s_route);
		nm_ip_route_unref (s_route);
	}

	/* DNS */
	for (i = 0; i < nnameservers; i++) {
		const struct in6_addr *nameserver = nm_ip6_config_get_nameserver (self, i);

		nm_setting_ip_config_add_dns (s_ip6, nm_utils_inet6_ntop (nameserver, sbuf));
	}
	for (i = 0; i < nsearches; i++) {
		const char *search = nm_ip6_config_get_search (self, i);

		nm_setting_ip_config_add_dns_search (s_ip6, search);
	}
	for (i = 0; i < noptions; i++) {
		const char *option = nm_ip6_config_get_dns_option (self, i);

		nm_setting_ip_config_add_dns_option (s_ip6, option);
	}

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_DNS_PRIORITY,
	              nm_ip6_config_get_dns_priority (self),
	              NULL);

	return NM_SETTING (s_ip6);
}

/*****************************************************************************/

void
nm_ip6_config_merge (NMIP6Config *dst,
                     const NMIP6Config *src,
                     NMIPConfigMergeFlags merge_flags,
                     guint32 default_route_metric_penalty)
{
	guint32 i;
	NMDedupMultiIter ipconf_iter;
	const NMPlatformIP6Address *address = NULL;

	g_return_if_fail (src != NULL);
	g_return_if_fail (dst != NULL);

	g_object_freeze_notify (G_OBJECT (dst));

	/* addresses */
	nm_ip_config_iter_ip6_address_for_each (&ipconf_iter, src, &address)
		_add_address (dst, NMP_OBJECT_UP_CAST (address), NULL);

	/* nameservers */
	if (!NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_DNS)) {
		for (i = 0; i < nm_ip6_config_get_num_nameservers (src); i++)
			nm_ip6_config_add_nameserver (dst, nm_ip6_config_get_nameserver (src, i));
	}

	/* routes */
	if (!NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_ROUTES)) {
		const NMPlatformIP6Route *r_src;

		nm_ip_config_iter_ip6_route_for_each (&ipconf_iter, src, &r_src) {
			if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT (r_src)) {
				if (NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_DEFAULT_ROUTES))
					continue;
				if (default_route_metric_penalty) {
					NMPlatformIP6Route r = *r_src;

					r.metric = nm_utils_ip_route_metric_penalize (AF_INET6, r.metric, default_route_metric_penalty);
					_add_route (dst, NULL, &r, NULL);
					continue;
				}
			}
			_add_route (dst, ipconf_iter.current->obj, NULL, NULL);
		}
	}

	/* domains */
	if (!NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_DNS)) {
		for (i = 0; i < nm_ip6_config_get_num_domains (src); i++)
			nm_ip6_config_add_domain (dst, nm_ip6_config_get_domain (src, i));
	}

	/* dns searches */
	if (!NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_DNS)) {
		for (i = 0; i < nm_ip6_config_get_num_searches (src); i++)
			nm_ip6_config_add_search (dst, nm_ip6_config_get_search (src, i));
	}

	/* dns options */
	if (!NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_DNS)) {
		for (i = 0; i < nm_ip6_config_get_num_dns_options (src); i++)
			nm_ip6_config_add_dns_option (dst, nm_ip6_config_get_dns_option (src, i));
	}

	/* DNS priority */
	if (nm_ip6_config_get_dns_priority (src))
		nm_ip6_config_set_dns_priority (dst, nm_ip6_config_get_dns_priority (src));

	g_object_thaw_notify (G_OBJECT (dst));
}

/*****************************************************************************/

static int
_nameservers_get_index (const NMIP6Config *self, const struct in6_addr *ns)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->nameservers->len; i++) {
		const struct in6_addr *n = &g_array_index (priv->nameservers, struct in6_addr, i);

		if (IN6_ARE_ADDR_EQUAL (ns, n))
			return (int) i;
	}
	return -1;
}

static int
_domains_get_index (const NMIP6Config *self, const char *domain)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->domains->len; i++) {
		const char *d = g_ptr_array_index (priv->domains, i);

		if (g_strcmp0 (domain, d) == 0)
			return (int) i;
	}
	return -1;
}

static int
_searches_get_index (const NMIP6Config *self, const char *search)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->searches->len; i++) {
		const char *s = g_ptr_array_index (priv->searches, i);

		if (g_strcmp0 (search, s) == 0)
			return (int) i;
	}
	return -1;
}

static int
_dns_options_get_index (const NMIP6Config *self, const char *option)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->dns_options->len; i++) {
		const char *s = g_ptr_array_index (priv->dns_options, i);

		if (g_strcmp0 (option, s) == 0)
			return (int) i;
	}
	return -1;
}

/*****************************************************************************/

/**
 * nm_ip6_config_subtract:
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
nm_ip6_config_subtract (NMIP6Config *dst,
                        const NMIP6Config *src,
                        guint32 default_route_metric_penalty)
{
	NMIP6ConfigPrivate *dst_priv;
	guint i;
	int idx;
	const NMPlatformIP6Address *a;
	const NMPlatformIP6Route *r;
	NMDedupMultiIter ipconf_iter;
	gboolean changed;
	gboolean changed_default_route;

	g_return_if_fail (src != NULL);
	g_return_if_fail (dst != NULL);

	dst_priv = NM_IP6_CONFIG_GET_PRIVATE (dst);

	g_object_freeze_notify (G_OBJECT (dst));

	/* addresses */
	changed = FALSE;
	nm_ip_config_iter_ip6_address_for_each (&ipconf_iter, src, &a) {
		if (nm_dedup_multi_index_remove_obj (dst_priv->multi_idx,
		                                     &dst_priv->idx_ip6_addresses,
		                                     NMP_OBJECT_UP_CAST (a),
		                                     NULL))
			changed = TRUE;
	}
	if (changed)
		_notify_addresses (dst);

	/* nameservers */
	for (i = 0; i < nm_ip6_config_get_num_nameservers (src); i++) {
		idx = _nameservers_get_index (dst, nm_ip6_config_get_nameserver (src, i));
		if (idx >= 0)
			nm_ip6_config_del_nameserver (dst, idx);
	}

	/* routes */
	changed = FALSE;
	changed_default_route = FALSE;
	nm_ip_config_iter_ip6_route_for_each (&ipconf_iter, src, &r) {
		const NMPObject *o_src = NMP_OBJECT_UP_CAST (r);
		NMPObject o_lookup_copy;
		const NMPObject *o_lookup;
		nm_auto_nmpobj const NMPObject *obj_old = NULL;

		if (   NM_PLATFORM_IP_ROUTE_IS_DEFAULT (r)
		    && default_route_metric_penalty) {
			NMPlatformIP6Route *rr;

			/* the default route was penalized when merging it to the combined ip-config.
			 * When subtracting the routes, we must re-do that process when comparing
			 * the routes. */
			o_lookup = nmp_object_stackinit_obj (&o_lookup_copy, o_src);
			rr = NMP_OBJECT_CAST_IP6_ROUTE (&o_lookup_copy);
			rr->metric = nm_utils_ip_route_metric_penalize (AF_INET6, rr->metric, default_route_metric_penalty);
		} else
			o_lookup = o_src;

		if (nm_dedup_multi_index_remove_obj (dst_priv->multi_idx,
		                                     &dst_priv->idx_ip6_routes,
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
		                                      _nm_ip6_config_best_default_route_find (dst));
		_notify (dst, PROP_GATEWAY);
	}
	if (changed)
		_notify_routes (dst);

	/* domains */
	for (i = 0; i < nm_ip6_config_get_num_domains (src); i++) {
		idx = _domains_get_index (dst, nm_ip6_config_get_domain (src, i));
		if (idx >= 0)
			nm_ip6_config_del_domain (dst, idx);
	}

	/* dns searches */
	for (i = 0; i < nm_ip6_config_get_num_searches (src); i++) {
		idx = _searches_get_index (dst, nm_ip6_config_get_search (src, i));
		if (idx >= 0)
			nm_ip6_config_del_search (dst, idx);
	}

	/* dns options */
	for (i = 0; i < nm_ip6_config_get_num_dns_options (src); i++) {
		idx = _dns_options_get_index (dst, nm_ip6_config_get_dns_option (src, i));
		if (idx >= 0)
			nm_ip6_config_del_dns_option (dst, idx);
	}

	/* DNS priority */
	if (nm_ip6_config_get_dns_priority (src) == nm_ip6_config_get_dns_priority (dst))
		nm_ip6_config_set_dns_priority (dst, 0);

	g_object_thaw_notify (G_OBJECT (dst));
}

static gboolean
_nm_ip6_config_intersect_helper (NMIP6Config *dst,
                                 const NMIP6Config *src,
                                 gboolean intersect_addresses,
                                 gboolean intersect_routes,
                                 guint32 default_route_metric_penalty,
                                 gboolean update_dst)
{
	NMIP6ConfigPrivate *dst_priv;
	const NMIP6ConfigPrivate *src_priv;
	NMDedupMultiIter ipconf_iter;
	const NMPlatformIP6Address *a;
	const NMPlatformIP6Route *r;
	gboolean changed, result = FALSE;
	const NMPObject *new_best_default_route;

	g_return_val_if_fail (src, FALSE);
	g_return_val_if_fail (dst, FALSE);

	dst_priv = NM_IP6_CONFIG_GET_PRIVATE (dst);
	src_priv = NM_IP6_CONFIG_GET_PRIVATE (src);

	if (update_dst)
		g_object_freeze_notify (G_OBJECT (dst));

	/* addresses */
	if (intersect_addresses) {
		changed = FALSE;
		nm_ip_config_iter_ip6_address_for_each (&ipconf_iter, dst, &a) {
			if (nm_dedup_multi_index_lookup_obj (src_priv->multi_idx,
			                                     &src_priv->idx_ip6_addresses,
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
	}

	/* ignore nameservers */

	/* routes */
	if (!intersect_routes)
		goto skip_routes;

	changed = FALSE;
	new_best_default_route = NULL;
	nm_ip_config_iter_ip6_route_for_each (&ipconf_iter, dst, &r) {
		const NMPObject *o_dst = NMP_OBJECT_UP_CAST (r);
		const NMPObject *o_lookup;
		NMPObject o_lookup_copy;

		if (   NM_PLATFORM_IP_ROUTE_IS_DEFAULT (r)
		    && default_route_metric_penalty) {
			NMPlatformIP6Route *rr;

			/* the default route was penalized when merging it to the combined ip-config.
			 * When intersecting the routes, we must re-do that process when comparing
			 * the routes. */
			o_lookup = nmp_object_stackinit_obj (&o_lookup_copy, o_dst);
			rr = NMP_OBJECT_CAST_IP6_ROUTE (&o_lookup_copy);
			rr->metric = nm_utils_ip_route_metric_penalize (AF_INET6, rr->metric, default_route_metric_penalty);
		} else
			o_lookup = o_dst;

		if (nm_dedup_multi_index_lookup_obj (src_priv->multi_idx,
		                                     &src_priv->idx_ip6_routes,
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

skip_routes:
	/* ignore domains */
	/* ignore dns searches */
	/* ignore dns options */

	if (update_dst)
		g_object_thaw_notify (G_OBJECT (dst));

	return result;
}

/**
 * nm_ip6_config_intersect:
 * @dst: a configuration to be updated
 * @src: another configuration
 * @intersect_addresses: whether addresses should be intersected
 * @intersect_routes: whether routes should be intersected
 * @default_route_metric_penalty: the default route metric penalty
 *
 * Computes the intersection between @src and @dst and updates @dst in place
 * with the result.
 */
void
nm_ip6_config_intersect (NMIP6Config *dst,
                         const NMIP6Config *src,
                         gboolean intersect_addresses,
                         gboolean intersect_routes,
                         guint32 default_route_metric_penalty)
{
	_nm_ip6_config_intersect_helper (dst,
	                                 src,
	                                 intersect_addresses,
	                                 intersect_routes,
	                                 default_route_metric_penalty,
	                                 TRUE);
}

/**
 * nm_ip6_config_intersect_alloc:
 * @a: a configuration
 * @b: another configuration
 * @intersect_addresses: whether addresses should be intersected
 * @intersect_routes: whether routes should be intersected
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
NMIP6Config *
nm_ip6_config_intersect_alloc (const NMIP6Config *a,
                               const NMIP6Config *b,
                               gboolean intersect_addresses,
                               gboolean intersect_routes,
                               guint32 default_route_metric_penalty)
{
	NMIP6Config *a_copy;

	if (_nm_ip6_config_intersect_helper ((NMIP6Config *) a,
	                                     b,
	                                     intersect_addresses,
	                                     intersect_routes,
	                                     default_route_metric_penalty,
	                                     FALSE)) {
		a_copy = nm_ip6_config_clone (a);
		_nm_ip6_config_intersect_helper (a_copy,
		                                 b,
		                                 intersect_addresses,
		                                 intersect_routes,
		                                 default_route_metric_penalty,
		                                 TRUE);
		return a_copy;
	} else
		return NULL;
}

/**
 * nm_ip6_config_replace:
 * @dst: config which will be replaced with everything in @src
 * @src: config to copy over to @dst
 * @relevant_changes: return whether there are changes to the
 * destination object that are relevant. This is equal to
 * nm_ip6_config_equal() showing any difference.
 *
 * Replaces everything in @dst with @src so that the two configurations
 * contain the same content -- with the exception of the dbus path.
 *
 * Returns: whether the @dst instance changed in any way (including minor changes,
 * that are not signaled by the output parameter @relevant_changes).
 */
gboolean
nm_ip6_config_replace (NMIP6Config *dst, const NMIP6Config *src, gboolean *relevant_changes)
{
#if NM_MORE_ASSERTS
	gboolean config_equal;
#endif
	gboolean has_minor_changes = FALSE, has_relevant_changes = FALSE, are_equal;
	guint i, num;
	NMIP6ConfigPrivate *dst_priv;
	const NMIP6ConfigPrivate *src_priv;
	NMDedupMultiIter ipconf_iter_src, ipconf_iter_dst;
	const NMDedupMultiHeadEntry *head_entry_src;
	const NMPObject *new_best_default_route;

	g_return_val_if_fail (NM_IS_IP6_CONFIG (src), FALSE);
	g_return_val_if_fail (NM_IS_IP6_CONFIG (dst), FALSE);
	g_return_val_if_fail (src != dst, FALSE);

#if NM_MORE_ASSERTS
	config_equal = nm_ip6_config_equal (dst, src);
#endif

	dst_priv = NM_IP6_CONFIG_GET_PRIVATE (dst);
	src_priv = NM_IP6_CONFIG_GET_PRIVATE (src);

	g_return_val_if_fail (src_priv->ifindex > 0, FALSE);

	g_object_freeze_notify (G_OBJECT (dst));

	/* ifindex */
	if (src_priv->ifindex != dst_priv->ifindex) {
		dst_priv->ifindex = src_priv->ifindex;
		has_minor_changes = TRUE;
	}

	/* addresses */
	head_entry_src = nm_ip6_config_lookup_addresses (src);
	nm_dedup_multi_iter_init (&ipconf_iter_src, head_entry_src);
	nm_ip_config_iter_ip6_address_init (&ipconf_iter_dst, dst);
	are_equal = TRUE;
	while (TRUE) {
		gboolean has;
		const NMPlatformIP6Address *r_src = NULL;
		const NMPlatformIP6Address *r_dst = NULL;

		has = nm_ip_config_iter_ip6_address_next (&ipconf_iter_src, &r_src);
		if (has != nm_ip_config_iter_ip6_address_next (&ipconf_iter_dst, &r_dst)) {
			are_equal = FALSE;
			has_relevant_changes = TRUE;
			break;
		}
		if (!has)
			break;

		if (nm_platform_ip6_address_cmp (r_src, r_dst) != 0) {
			are_equal = FALSE;
			if (   !IN6_ARE_ADDR_EQUAL (&r_src->address, &r_dst->address)
			    || r_src->plen != r_dst->plen
			    || !IN6_ARE_ADDR_EQUAL (nm_platform_ip6_address_get_peer (r_src),
			                            nm_platform_ip6_address_get_peer (r_dst))) {
				has_relevant_changes = TRUE;
				break;
			}
		}
	}
	if (!are_equal) {
		has_minor_changes = TRUE;
		nm_dedup_multi_index_dirty_set_idx (dst_priv->multi_idx, &dst_priv->idx_ip6_addresses);
		nm_dedup_multi_iter_for_each (&ipconf_iter_src, head_entry_src) {
			_nm_ip_config_add_obj (dst_priv->multi_idx,
			                       &dst_priv->idx_ip6_addresses_,
			                       dst_priv->ifindex,
			                       ipconf_iter_src.current->obj,
			                       NULL,
			                       FALSE,
			                       TRUE,
			                       NULL,
			                       NULL);
		}
		nm_dedup_multi_index_dirty_remove_idx (dst_priv->multi_idx, &dst_priv->idx_ip6_addresses, FALSE);
		_notify_addresses (dst);
	}

	/* routes */
	head_entry_src = nm_ip6_config_lookup_routes (src);
	nm_dedup_multi_iter_init (&ipconf_iter_src, head_entry_src);
	nm_ip_config_iter_ip6_route_init (&ipconf_iter_dst, dst);
	are_equal = TRUE;
	while (TRUE) {
		gboolean has;
		const NMPlatformIP6Route *r_src = NULL;
		const NMPlatformIP6Route *r_dst = NULL;

		has = nm_ip_config_iter_ip6_route_next (&ipconf_iter_src, &r_src);
		if (has != nm_ip_config_iter_ip6_route_next (&ipconf_iter_dst, &r_dst)) {
			are_equal = FALSE;
			has_relevant_changes = TRUE;
			break;
		}
		if (!has)
			break;

		if (nm_platform_ip6_route_cmp_full (r_src, r_dst) != 0) {
			are_equal = FALSE;
			if (   r_src->plen != r_dst->plen
			    || !nm_utils_ip6_address_same_prefix (&r_src->network, &r_dst->network, r_src->plen)
			    || r_src->metric != r_dst->metric
			    || !IN6_ARE_ADDR_EQUAL (&r_src->gateway, &r_dst->gateway)) {
				has_relevant_changes = TRUE;
				break;
			}
		}
	}
	if (!are_equal) {
		has_minor_changes = TRUE;
		new_best_default_route = NULL;
		nm_dedup_multi_index_dirty_set_idx (dst_priv->multi_idx, &dst_priv->idx_ip6_routes);
		nm_dedup_multi_iter_for_each (&ipconf_iter_src, head_entry_src) {
			const NMPObject *o = ipconf_iter_src.current->obj;
			const NMPObject *obj_new;

			_nm_ip_config_add_obj (dst_priv->multi_idx,
			                       &dst_priv->idx_ip6_routes_,
			                       dst_priv->ifindex,
			                       o,
			                       NULL,
			                       FALSE,
			                       TRUE,
			                       NULL,
			                       &obj_new);
			new_best_default_route = _nm_ip_config_best_default_route_find_better (new_best_default_route, obj_new);
		}
		nm_dedup_multi_index_dirty_remove_idx (dst_priv->multi_idx, &dst_priv->idx_ip6_routes, FALSE);
		if (_nm_ip_config_best_default_route_set (&dst_priv->best_default_route, new_best_default_route))
			_notify (dst, PROP_GATEWAY);
		_notify_routes (dst);
	}

	/* nameservers */
	num = nm_ip6_config_get_num_nameservers (src);
	are_equal = num == nm_ip6_config_get_num_nameservers (dst);
	if (are_equal) {
		for (i = 0; i < num; i++ ) {
			if (!IN6_ARE_ADDR_EQUAL (nm_ip6_config_get_nameserver (src, i),
			                         nm_ip6_config_get_nameserver (dst, i))) {
				are_equal = FALSE;
				break;
			}
		}
	}
	if (!are_equal) {
		nm_ip6_config_reset_nameservers (dst);
		for (i = 0; i < num; i++)
			nm_ip6_config_add_nameserver (dst, nm_ip6_config_get_nameserver (src, i));
		has_relevant_changes = TRUE;
	}

	/* domains */
	num = nm_ip6_config_get_num_domains (src);
	are_equal = num == nm_ip6_config_get_num_domains (dst);
	if (are_equal) {
		for (i = 0; i < num; i++ ) {
			if (g_strcmp0 (nm_ip6_config_get_domain (src, i),
			                nm_ip6_config_get_domain (dst, i))) {
				are_equal = FALSE;
				break;
			}
		}
	}
	if (!are_equal) {
		nm_ip6_config_reset_domains (dst);
		for (i = 0; i < num; i++)
			nm_ip6_config_add_domain (dst, nm_ip6_config_get_domain (src, i));
		has_relevant_changes = TRUE;
	}

	/* dns searches */
	num = nm_ip6_config_get_num_searches (src);
	are_equal = num == nm_ip6_config_get_num_searches (dst);
	if (are_equal) {
		for (i = 0; i < num; i++ ) {
			if (g_strcmp0 (nm_ip6_config_get_search (src, i),
			                nm_ip6_config_get_search (dst, i))) {
				are_equal = FALSE;
				break;
			}
		}
	}
	if (!are_equal) {
		nm_ip6_config_reset_searches (dst);
		for (i = 0; i < num; i++)
			nm_ip6_config_add_search (dst, nm_ip6_config_get_search (src, i));
		has_relevant_changes = TRUE;
	}

	/* dns options */
	num = nm_ip6_config_get_num_dns_options (src);
	are_equal = num == nm_ip6_config_get_num_dns_options (dst);
	if (are_equal) {
		for (i = 0; i < num; i++ ) {
			if (g_strcmp0 (nm_ip6_config_get_dns_option (src, i),
			               nm_ip6_config_get_dns_option (dst, i))) {
				are_equal = FALSE;
				break;
			}
		}
	}
	if (!are_equal) {
		nm_ip6_config_reset_dns_options (dst);
		for (i = 0; i < num; i++)
			nm_ip6_config_add_dns_option (dst, nm_ip6_config_get_dns_option (src, i));
		has_relevant_changes = TRUE;
	}

	/* DNS priority */
	if (src_priv->dns_priority != dst_priv->dns_priority) {
		nm_ip6_config_set_dns_priority (dst, src_priv->dns_priority);
		has_minor_changes = TRUE;
	}

	if (src_priv->privacy != dst_priv->privacy) {
		nm_ip6_config_set_privacy (dst, src_priv->privacy);
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

/*****************************************************************************/

void
nm_ip6_config_reset_addresses_ndisc (NMIP6Config *self,
                                     const NMNDiscAddress *addresses,
                                     guint addresses_n,
                                     guint8 plen,
                                     guint32 ifa_flags)
{
	NMIP6ConfigPrivate *priv;
	guint i;
	gboolean changed = FALSE;

	g_return_if_fail (NM_IS_IP6_CONFIG (self));

	priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	g_return_if_fail (priv->ifindex > 0);

	nm_dedup_multi_index_dirty_set_idx (priv->multi_idx, &priv->idx_ip6_addresses);

	for (i = 0; i < addresses_n; i++) {
		const NMNDiscAddress *ndisc_addr = &addresses[i];
		NMPObject obj;
		NMPlatformIP6Address *a;

		nmp_object_stackinit (&obj, NMP_OBJECT_TYPE_IP6_ADDRESS, NULL);
		a = NMP_OBJECT_CAST_IP6_ADDRESS (&obj);
		a->ifindex     = priv->ifindex;
		a->address     = ndisc_addr->address;
		a->plen        = plen;
		a->timestamp   = ndisc_addr->timestamp;
		a->lifetime    = ndisc_addr->lifetime;
		a->preferred   = MIN (ndisc_addr->lifetime, ndisc_addr->preferred);
		a->addr_source = NM_IP_CONFIG_SOURCE_NDISC;
		a->n_ifa_flags = ifa_flags;

		if (_nm_ip_config_add_obj (priv->multi_idx,
		                           &priv->idx_ip6_addresses_,
		                           priv->ifindex,
		                           &obj,
		                           NULL,
		                           FALSE,
		                           TRUE,
		                           NULL,
		                           NULL))
			changed = TRUE;
	}

	if (nm_dedup_multi_index_dirty_remove_idx (priv->multi_idx, &priv->idx_ip6_addresses, FALSE) > 0)
		changed = TRUE;

	if (changed)
		_notify_addresses (self);
}

void
nm_ip6_config_reset_addresses (NMIP6Config *self)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	if (nm_dedup_multi_index_remove_idx (priv->multi_idx,
	                                     &priv->idx_ip6_addresses) > 0)
		_notify_addresses (self);
}

static void
_add_address (NMIP6Config *self,
              const NMPObject *obj_new,
              const NMPlatformIP6Address *new)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	if (_nm_ip_config_add_obj (priv->multi_idx,
	                           &priv->idx_ip6_addresses_,
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
 * nm_ip6_config_add_address:
 * @self: the #NMIP6Config
 * @new: the new address to add to @self
 *
 * Adds the new address to @self.  If an address with the same basic properties
 * (address, prefix) already exists in @self, it is overwritten with the
 * lifetime and preferred of @new.  The source is also overwritten by the source
 * from @new if that source is higher priority.
 */
void
nm_ip6_config_add_address (NMIP6Config *self, const NMPlatformIP6Address *new)
{
	g_return_if_fail (self);
	g_return_if_fail (new);
	g_return_if_fail (new->plen <= 128);
	g_return_if_fail (NM_IP6_CONFIG_GET_PRIVATE (self)->ifindex > 0);

	_add_address (self, NULL, new);
}

void
_nmtst_ip6_config_del_address (NMIP6Config *self, guint i)
{
	const NMPlatformIP6Address *a;

	a = _nmtst_ip6_config_get_address (self, i);
	if (!nm_ip6_config_nmpobj_remove (self,
	                                  NMP_OBJECT_UP_CAST (a)))
		g_assert_not_reached ();
}

guint
nm_ip6_config_get_num_addresses (const NMIP6Config *self)
{
	const NMDedupMultiHeadEntry *head_entry;

	head_entry = nm_ip6_config_lookup_addresses (self);
	return head_entry ? head_entry->len : 0;
}

const NMPlatformIP6Address *
nm_ip6_config_get_first_address (const NMIP6Config *self)
{
	NMDedupMultiIter iter;
	const NMPlatformIP6Address *a = NULL;

	nm_ip_config_iter_ip6_address_for_each (&iter, self, &a)
		return a;
	return NULL;
}

const NMPlatformIP6Address *
_nmtst_ip6_config_get_address (const NMIP6Config *self, guint i)
{
	NMDedupMultiIter iter;
	const NMPlatformIP6Address *a = NULL;
	guint j;

	j = 0;
	nm_ip_config_iter_ip6_address_for_each (&iter, self, &a) {
		if (i == j)
			return a;
		j++;
	}
	g_return_val_if_reached (NULL);
}

const NMPlatformIP6Address *
nm_ip6_config_lookup_address (const NMIP6Config *self,
                              const struct in6_addr *addr)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	NMPObject obj_stack;
	const NMDedupMultiEntry *entry;

	nmp_object_stackinit_id_ip6_address (&obj_stack,
	                                     priv->ifindex,
	                                     addr);
	entry = nm_dedup_multi_index_lookup_obj (priv->multi_idx,
	                                         &priv->idx_ip6_addresses,
	                                         &obj_stack);
	return entry
	       ? NMP_OBJECT_CAST_IP6_ADDRESS (entry->obj)
	       : NULL;
}

const NMPlatformIP6Address *
nm_ip6_config_find_first_address (const NMIP6Config *self,
                                  NMPlatformMatchFlags match_flag)
{
	const NMPlatformIP6Address *addr;
	NMDedupMultiIter iter;

	g_return_val_if_fail (NM_IS_IP6_CONFIG (self), NULL);

	nm_assert (!NM_FLAGS_ANY (match_flag, ~(  NM_PLATFORM_MATCH_WITH_ADDRTYPE__ANY
	                                        | NM_PLATFORM_MATCH_WITH_ADDRSTATE__ANY)));

	nm_assert (NM_FLAGS_ANY (match_flag, NM_PLATFORM_MATCH_WITH_ADDRTYPE__ANY));
	nm_assert (NM_FLAGS_ANY (match_flag, NM_PLATFORM_MATCH_WITH_ADDRSTATE__ANY));

	nm_ip_config_iter_ip6_address_for_each (&iter, self, &addr) {

		if (IN6_IS_ADDR_LINKLOCAL (&addr->address)) {
			if (!NM_FLAGS_HAS (match_flag, NM_PLATFORM_MATCH_WITH_ADDRTYPE_LINKLOCAL))
				continue;
		} else {
			if (!NM_FLAGS_HAS (match_flag, NM_PLATFORM_MATCH_WITH_ADDRTYPE_NORMAL))
				continue;
		}

		if (NM_FLAGS_HAS (addr->n_ifa_flags, IFA_F_DADFAILED)) {
			if (!NM_FLAGS_HAS (match_flag, NM_PLATFORM_MATCH_WITH_ADDRSTATE_DADFAILED))
				continue;
		} else if (   NM_FLAGS_HAS (addr->n_ifa_flags, IFA_F_TENTATIVE)
		           && !NM_FLAGS_HAS (addr->n_ifa_flags, IFA_F_OPTIMISTIC)) {
			if (!NM_FLAGS_HAS (match_flag, NM_PLATFORM_MATCH_WITH_ADDRSTATE_TENTATIVE))
				continue;
		} else {
			if (!NM_FLAGS_HAS (match_flag, NM_PLATFORM_MATCH_WITH_ADDRSTATE_NORMAL))
				continue;
		}

		return addr;
	}

	return NULL;
}

/**
 * nm_ip6_config_has_dad_pending_addresses
 * @self: configuration containing the addresses to check
 * @candidates: configuration with the list of addresses we are
 *   interested in
 *
 * Check whether there are addresses with DAD pending in @self, that
 * are also contained in @candidates.
 *
 * Returns: %TRUE if at least one matching address was found, %FALSE
 *   otherwise
 */
gboolean
nm_ip6_config_has_any_dad_pending (const NMIP6Config *self,
                                   const NMIP6Config *candidates)
{
	NMDedupMultiIter ipconf_iter;
	const NMPlatformIP6Address *addr, *addr_c;

	nm_ip_config_iter_ip6_address_for_each (&ipconf_iter, self, &addr) {
		if (   NM_FLAGS_HAS (addr->n_ifa_flags, IFA_F_TENTATIVE)
		    && !NM_FLAGS_HAS (addr->n_ifa_flags, IFA_F_DADFAILED)
		    && !NM_FLAGS_HAS (addr->n_ifa_flags, IFA_F_OPTIMISTIC)) {
			addr_c = nm_ip6_config_lookup_address (candidates, &addr->address);
			if (addr_c) {
				if (addr->plen == addr_c->plen)
					return TRUE;
			}
		}
	}

	return FALSE;
}

/*****************************************************************************/

static const NMDedupMultiEntry *
_lookup_route (const NMIP6Config *self,
               const NMPObject *needle,
               NMPlatformIPRouteCmpType cmp_type)
{
	const NMIP6ConfigPrivate *priv;

	nm_assert (NM_IS_IP6_CONFIG (self));
	nm_assert (NMP_OBJECT_GET_TYPE (needle) == NMP_OBJECT_TYPE_IP6_ROUTE);

	priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	return _nm_ip_config_lookup_ip_route (priv->multi_idx,
	                                      &priv->idx_ip6_routes_,
	                                      needle,
	                                      cmp_type);
}

void
nm_ip6_config_reset_routes_ndisc (NMIP6Config *self,
                                  const NMNDiscGateway *gateways,
                                  guint gateways_n,
                                  const NMNDiscRoute *routes,
                                  guint routes_n,
                                  guint32 route_table,
                                  guint32 route_metric,
                                  gboolean kernel_support_rta_pref)
{
	NMIP6ConfigPrivate *priv;
	guint i;
	gboolean changed = FALSE;
	const NMPObject *new_best_default_route;

	g_return_if_fail (NM_IS_IP6_CONFIG (self));

	priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	g_return_if_fail (priv->ifindex > 0);

	nm_dedup_multi_index_dirty_set_idx (priv->multi_idx, &priv->idx_ip6_routes);

	new_best_default_route = NULL;
	for (i = 0; i < routes_n; i++) {
		const NMNDiscRoute *ndisc_route = &routes[i];
		NMPObject obj;
		const NMPObject *obj_new;
		NMPlatformIP6Route *r;

		nmp_object_stackinit (&obj, NMP_OBJECT_TYPE_IP6_ROUTE, NULL);
		r = NMP_OBJECT_CAST_IP6_ROUTE (&obj);
		r->ifindex    = priv->ifindex;
		r->network    = ndisc_route->network;
		r->plen       = ndisc_route->plen;
		r->gateway    = ndisc_route->gateway;
		r->rt_source  = NM_IP_CONFIG_SOURCE_NDISC;
		r->table_coerced = nm_platform_route_table_coerce (route_table);
		r->metric     = route_metric;
		r->rt_pref    = ndisc_route->preference;
		nm_assert ((NMIcmpv6RouterPref) r->rt_pref == ndisc_route->preference);

		if (_nm_ip_config_add_obj (priv->multi_idx,
		                           &priv->idx_ip6_routes_,
		                           priv->ifindex,
		                           &obj,
		                           NULL,
		                           FALSE,
		                           TRUE,
		                           NULL,
		                           &obj_new))
			changed = TRUE;
		new_best_default_route = _nm_ip_config_best_default_route_find_better (new_best_default_route, obj_new);
	}

	if (gateways_n) {
		const NMPObject *obj_new;
		NMPlatformIP6Route r = {
			.rt_source     = NM_IP_CONFIG_SOURCE_NDISC,
			.ifindex       = priv->ifindex,
			.table_coerced = nm_platform_route_table_coerce (route_table),
			.metric        = route_metric,
		};
		const NMIcmpv6RouterPref first_pref = gateways[0].preference;

		for (i = 0; i < gateways_n; i++) {
			r.gateway = gateways[i].address;
			r.rt_pref = gateways[i].preference;
			nm_assert ((NMIcmpv6RouterPref) r.rt_pref == gateways[i].preference);
			if (_nm_ip_config_add_obj (priv->multi_idx,
			                           &priv->idx_ip6_routes_,
			                           priv->ifindex,
			                           NULL,
			                           (const NMPlatformObject *) &r,
			                           FALSE,
			                           TRUE,
			                           NULL,
			                           &obj_new))
				changed = TRUE;
			new_best_default_route = _nm_ip_config_best_default_route_find_better (new_best_default_route, obj_new);

			if (   first_pref != gateways[i].preference
			    && !kernel_support_rta_pref) {
				/* We are unable to configure a router preference. Hence, we skip all gateways
				 * with a different preference from the first gateway. Note, that the gateways
				 * are sorted in order of highest to lowest preference. */
				break;
			}
		}
	}

	if (nm_dedup_multi_index_dirty_remove_idx (priv->multi_idx, &priv->idx_ip6_routes, FALSE) > 0)
		changed = TRUE;

	if (_nm_ip_config_best_default_route_set (&priv->best_default_route, new_best_default_route)) {
		changed = TRUE;
		_notify (self, PROP_GATEWAY);
	}

	if (changed)
		_notify_routes (self);
}

void
nm_ip6_config_reset_routes (NMIP6Config *self)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	if (nm_dedup_multi_index_remove_idx (priv->multi_idx,
	                                     &priv->idx_ip6_routes) > 0) {
		if (nm_clear_nmp_object (&priv->best_default_route))
			_notify (self, PROP_GATEWAY);
		_notify_routes (self);
	}
}

static void
_add_route (NMIP6Config *self,
            const NMPObject *obj_new,
            const NMPlatformIP6Route *new,
            const NMPObject **out_obj_new)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	nm_auto_nmpobj const NMPObject *obj_old = NULL;
	const NMPObject *obj_new_2;

	nm_assert ((!new) != (!obj_new));
	nm_assert (!new || _route_valid (new));
	nm_assert (!obj_new || _route_valid (NMP_OBJECT_CAST_IP6_ROUTE (obj_new)));

	if (_nm_ip_config_add_obj (priv->multi_idx,
	                           &priv->idx_ip6_routes_,
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
 * nm_ip6_config_add_route:
 * @self: the #NMIP6Config
 * @new: the new route to add to @self
 * @out_obj_new: (allow-none) (out): the added route object. Must be unrefed
 *   by caller.
 *
 * Adds the new route to @self.  If a route with the same basic properties
 * (network, prefix) already exists in @self, it is overwritten including the
 * gateway and metric of @new.  The source is also overwritten by the source
 * from @new if that source is higher priority.
 */
void
nm_ip6_config_add_route (NMIP6Config *self,
                         const NMPlatformIP6Route *new,
                         const NMPObject **out_obj_new)
{
	g_return_if_fail (self);
	g_return_if_fail (new);
	g_return_if_fail (new->plen <= 128);
	g_return_if_fail (NM_IP6_CONFIG_GET_PRIVATE (self)->ifindex > 0);

	_add_route (self, NULL, new, out_obj_new);
}

void
_nmtst_ip6_config_del_route (NMIP6Config *self, guint i)
{
	const NMPlatformIP6Route *r;

	r = _nmtst_ip6_config_get_route (self, i);
	if (!nm_ip6_config_nmpobj_remove (self,
	                                  NMP_OBJECT_UP_CAST (r)))
		g_assert_not_reached ();
}

guint
nm_ip6_config_get_num_routes (const NMIP6Config *self)
{
	const NMDedupMultiHeadEntry *head_entry;

	head_entry = nm_ip6_config_lookup_routes (self);
	nm_assert (!head_entry || head_entry->len == c_list_length (&head_entry->lst_entries_head));
	return head_entry ? head_entry->len : 0;
}

const NMPlatformIP6Route *
_nmtst_ip6_config_get_route (const NMIP6Config *self, guint i)
{
	NMDedupMultiIter iter;
	const NMPlatformIP6Route *r = NULL;
	guint j;

	j = 0;
	nm_ip_config_iter_ip6_route_for_each (&iter, self, &r) {
		if (i == j)
			return r;
		j++;
	}
	g_return_val_if_reached (NULL);
}

const NMPlatformIP6Route *
nm_ip6_config_get_direct_route_for_host (const NMIP6Config *self,
                                         const struct in6_addr *host,
                                         guint32 route_table)
{
	const NMPlatformIP6Route *best_route = NULL;
	const NMPlatformIP6Route *item;
	NMDedupMultiIter ipconf_iter;

	g_return_val_if_fail (host && !IN6_IS_ADDR_UNSPECIFIED (host), NULL);

	nm_ip_config_iter_ip6_route_for_each (&ipconf_iter, self, &item) {
		if (!IN6_IS_ADDR_UNSPECIFIED (&item->gateway))
			continue;

		if (best_route && best_route->plen > item->plen)
			continue;

		if (nm_platform_route_table_uncoerce (item->table_coerced, TRUE) != route_table)
			continue;

		if (!nm_utils_ip6_address_same_prefix (host, &item->network, item->plen))
			continue;

		if (best_route &&
		    nm_utils_ip6_route_metric_normalize (best_route->metric) <= nm_utils_ip6_route_metric_normalize (item->metric))
			continue;

		best_route = item;
	}
	return best_route;
}

const NMPlatformIP6Address *
nm_ip6_config_get_subnet_for_host (const NMIP6Config *self, const struct in6_addr *host)
{
	NMDedupMultiIter iter;
	const NMPlatformIP6Address *item;
	const NMPlatformIP6Address *subnet = NULL;
	struct in6_addr subnet2, host2;

	g_return_val_if_fail (host && !IN6_IS_ADDR_UNSPECIFIED (host), NULL);

	nm_ip_config_iter_ip6_address_for_each (&iter, self, &item) {
		if (subnet && subnet->plen >= item->plen)
			continue;

		nm_utils_ip6_address_clear_host_address (&host2, host, item->plen);
		nm_utils_ip6_address_clear_host_address (&subnet2, &item->address, item->plen);

		if (IN6_ARE_ADDR_EQUAL (&subnet2, &host2))
			subnet = item;
	}

	return subnet;
}

/*****************************************************************************/

void
nm_ip6_config_reset_nameservers (NMIP6Config *self)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	if (priv->nameservers->len != 0) {
		g_array_set_size (priv->nameservers, 0);
		_notify (self, PROP_NAMESERVERS);
	}
}

void
nm_ip6_config_add_nameserver (NMIP6Config *self, const struct in6_addr *new)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	int i;

	g_return_if_fail (new != NULL);

	for (i = 0; i < priv->nameservers->len; i++)
		if (IN6_ARE_ADDR_EQUAL (new, &g_array_index (priv->nameservers, struct in6_addr, i)))
			return;

	g_array_append_val (priv->nameservers, *new);
	_notify (self, PROP_NAMESERVERS);
}

void
nm_ip6_config_del_nameserver (NMIP6Config *self, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	g_return_if_fail (i < priv->nameservers->len);

	g_array_remove_index (priv->nameservers, i);
	_notify (self, PROP_NAMESERVERS);
}

guint
nm_ip6_config_get_num_nameservers (const NMIP6Config *self)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	return priv->nameservers->len;
}

const struct in6_addr *
nm_ip6_config_get_nameserver (const NMIP6Config *self, guint i)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	return &g_array_index (priv->nameservers, struct in6_addr, i);
}

/*****************************************************************************/

void
nm_ip6_config_reset_domains (NMIP6Config *self)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	if (priv->domains->len != 0) {
		g_ptr_array_set_size (priv->domains, 0);
		_notify (self, PROP_DOMAINS);
	}
}

void
nm_ip6_config_add_domain (NMIP6Config *self, const char *domain)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	if (_nm_ip_config_check_and_add_domain (priv->domains, domain))
		_notify (self, PROP_DOMAINS);
}

void
nm_ip6_config_del_domain (NMIP6Config *self, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	g_return_if_fail (i < priv->domains->len);

	g_ptr_array_remove_index (priv->domains, i);
	_notify (self, PROP_DOMAINS);
}

guint
nm_ip6_config_get_num_domains (const NMIP6Config *self)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	return priv->domains->len;
}

const char *
nm_ip6_config_get_domain (const NMIP6Config *self, guint i)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	return g_ptr_array_index (priv->domains, i);
}

/*****************************************************************************/

void
nm_ip6_config_reset_searches (NMIP6Config *self)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	if (priv->searches->len != 0) {
		g_ptr_array_set_size (priv->searches, 0);
		_notify (self, PROP_SEARCHES);
	}
}

void
nm_ip6_config_add_search (NMIP6Config *self, const char *search)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	if (_nm_ip_config_check_and_add_domain (priv->searches, search))
		_notify (self, PROP_SEARCHES);
}

void
nm_ip6_config_del_search (NMIP6Config *self, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	g_return_if_fail (i < priv->searches->len);

	g_ptr_array_remove_index (priv->searches, i);
	_notify (self, PROP_SEARCHES);
}

guint
nm_ip6_config_get_num_searches (const NMIP6Config *self)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	return priv->searches->len;
}

const char *
nm_ip6_config_get_search (const NMIP6Config *self, guint i)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	return g_ptr_array_index (priv->searches, i);
}

/*****************************************************************************/

void
nm_ip6_config_reset_dns_options (NMIP6Config *self)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	if (priv->dns_options->len != 0) {
		g_ptr_array_set_size (priv->dns_options, 0);
		_notify (self, PROP_DNS_OPTIONS);
	}
}

void
nm_ip6_config_add_dns_option (NMIP6Config *self, const char *new)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
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
nm_ip6_config_del_dns_option (NMIP6Config *self, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	g_return_if_fail (i < priv->dns_options->len);

	g_ptr_array_remove_index (priv->dns_options, i);
	_notify (self, PROP_DNS_OPTIONS);
}

guint
nm_ip6_config_get_num_dns_options (const NMIP6Config *self)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	return priv->dns_options->len;
}

const char *
nm_ip6_config_get_dns_option (const NMIP6Config *self, guint i)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	return g_ptr_array_index (priv->dns_options, i);
}

/*****************************************************************************/

void
nm_ip6_config_set_dns_priority (NMIP6Config *self, int priority)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	if (priority != priv->dns_priority) {
		priv->dns_priority = priority;
		_notify (self, PROP_DNS_PRIORITY);
	}
}

int
nm_ip6_config_get_dns_priority (const NMIP6Config *self)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	return priv->dns_priority;
}

/*****************************************************************************/

const NMPObject *
nm_ip6_config_nmpobj_lookup (const NMIP6Config *self, const NMPObject *needle)
{
	const NMIP6ConfigPrivate *priv;
	const NMDedupMultiIdxType *idx_type;

	g_return_val_if_fail (NM_IS_IP6_CONFIG (self), NULL);

	priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	switch (NMP_OBJECT_GET_TYPE (needle)) {
	case NMP_OBJECT_TYPE_IP6_ADDRESS:
		idx_type = &priv->idx_ip6_addresses;
		break;
	case NMP_OBJECT_TYPE_IP6_ROUTE:
		idx_type = &priv->idx_ip6_routes;
		break;
	default:
		g_return_val_if_reached (NULL);
	}

	return nm_dedup_multi_entry_get_obj (nm_dedup_multi_index_lookup_obj (priv->multi_idx,
	                                                                      idx_type,
	                                                                      needle));
}

gboolean
nm_ip6_config_nmpobj_remove (NMIP6Config *self,
                             const NMPObject *needle)
{
	NMIP6ConfigPrivate *priv;
	NMDedupMultiIdxType *idx_type;
	nm_auto_nmpobj const NMPObject *obj_old = NULL;
	guint n;

	g_return_val_if_fail (NM_IS_IP6_CONFIG (self), FALSE);

	priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	switch (NMP_OBJECT_GET_TYPE (needle)) {
	case NMP_OBJECT_TYPE_IP6_ADDRESS:
		idx_type = &priv->idx_ip6_addresses;
		break;
	case NMP_OBJECT_TYPE_IP6_ROUTE:
		idx_type = &priv->idx_ip6_routes;
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
	case NMP_OBJECT_TYPE_IP6_ADDRESS:
		_notify_addresses (self);
		break;
	case NMP_OBJECT_TYPE_IP6_ROUTE:
		if (priv->best_default_route == obj_old) {
			if (_nm_ip_config_best_default_route_set (&priv->best_default_route,
			                                          _nm_ip6_config_best_default_route_find (self)))
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

static void
hash_u32 (GChecksum *sum, guint32 n)
{
	g_checksum_update (sum, (const guint8 *) &n, sizeof (n));
}

static void
hash_in6addr (GChecksum *sum, const struct in6_addr *a)
{
	if (a)
		g_checksum_update (sum, (const guint8 *) a, sizeof (*a));
	else
		g_checksum_update (sum, (const guint8 *) &in6addr_any, sizeof (in6addr_any));
}

void
nm_ip6_config_hash (const NMIP6Config *self, GChecksum *sum, gboolean dns_only)
{
	guint32 i;
	const char *s;
	NMDedupMultiIter ipconf_iter;
	const NMPlatformIP6Address *address;
	const NMPlatformIP6Route *route;

	g_return_if_fail (self);
	g_return_if_fail (sum);

	if (dns_only == FALSE) {
		nm_ip_config_iter_ip6_address_for_each (&ipconf_iter, self, &address) {
			hash_in6addr (sum, &address->address);
			hash_u32 (sum, address->plen);
		}

		nm_ip_config_iter_ip6_route_for_each (&ipconf_iter, self, &route) {
			hash_in6addr (sum, &route->network);
			hash_u32 (sum, route->plen);
			hash_in6addr (sum, &route->gateway);
			hash_u32 (sum, route->metric);
		}
	}

	for (i = 0; i < nm_ip6_config_get_num_nameservers (self); i++)
		hash_in6addr (sum, nm_ip6_config_get_nameserver (self, i));

	for (i = 0; i < nm_ip6_config_get_num_domains (self); i++) {
		s = nm_ip6_config_get_domain (self, i);
		g_checksum_update (sum, (const guint8 *) s, strlen (s));
	}

	for (i = 0; i < nm_ip6_config_get_num_searches (self); i++) {
		s = nm_ip6_config_get_search (self, i);
		g_checksum_update (sum, (const guint8 *) s, strlen (s));
	}

	for (i = 0; i < nm_ip6_config_get_num_dns_options (self); i++) {
		s = nm_ip6_config_get_dns_option (self, i);
		g_checksum_update (sum, (const guint8 *) s, strlen (s));
	}
}

/**
 * nm_ip6_config_equal:
 * @a: first config to compare
 * @b: second config to compare
 *
 * Compares two #NMIP6Configs for basic equality.  This means that all
 * attributes must exist in the same order in both configs (addresses, routes,
 * domains, DNS servers, etc) but some attributes (address lifetimes, and address
 * and route sources) are ignored.
 *
 * Returns: %TRUE if the configurations are basically equal to each other,
 * %FALSE if not
 */
gboolean
nm_ip6_config_equal (const NMIP6Config *a, const NMIP6Config *b)
{
	nm_auto_free_checksum GChecksum *a_checksum = g_checksum_new (G_CHECKSUM_SHA1);
	nm_auto_free_checksum GChecksum *b_checksum = g_checksum_new (G_CHECKSUM_SHA1);
	guint8 a_data[NM_UTILS_CHECKSUM_LENGTH_SHA1];
	guint8 b_data[NM_UTILS_CHECKSUM_LENGTH_SHA1];

	if (a)
		nm_ip6_config_hash (a, a_checksum, FALSE);
	if (b)
		nm_ip6_config_hash (b, b_checksum, FALSE);

	nm_utils_checksum_get_digest (a_checksum, a_data);
	nm_utils_checksum_get_digest (b_checksum, b_data);
	return !memcmp (a_data, b_data, sizeof (a_data));
}

/*****************************************************************************/

static void
nameservers_to_gvalue (GArray *array, GValue *value)
{
	GVariantBuilder builder;
	guint i = 0;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aay"));

	while (array && (i < array->len)) {
		struct in6_addr *addr;

		addr = &g_array_index (array, struct in6_addr, i++);
		g_variant_builder_add (&builder, "@ay",
		                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                                  addr, 16, 1));
	}

	g_value_take_variant (value, g_variant_builder_end (&builder));
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMIP6Config *self = NM_IP6_CONFIG (object);
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	const NMDedupMultiHeadEntry *head_entry;
	NMDedupMultiIter ipconf_iter;
	const NMPlatformIP6Route *route;
	GVariantBuilder builder_data, builder_legacy;
	char sbuf[NM_UTILS_INET_ADDRSTRLEN];

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
		g_variant_builder_init (&builder_legacy, G_VARIANT_TYPE ("a(ayuay)"));

		head_entry = nm_ip6_config_lookup_addresses (self);
		if (head_entry) {
			gs_free const NMPObject **addresses = NULL;
			guint naddr, i;

			addresses = (const NMPObject **) nm_dedup_multi_objs_to_array_head (head_entry, NULL, NULL, &naddr);
			nm_assert (addresses && naddr);

			g_qsort_with_data (addresses,
			                   naddr,
			                   sizeof (addresses[0]),
			                   _addresses_sort_cmp_prop,
			                   GINT_TO_POINTER (priv->privacy));

			for (i = 0; i < naddr; i++) {
				GVariantBuilder addr_builder;
				const NMPlatformIP6Address *address = NMP_OBJECT_CAST_IP6_ADDRESS (addresses[i]);

				g_variant_builder_init (&addr_builder, G_VARIANT_TYPE ("a{sv}"));
				g_variant_builder_add (&addr_builder, "{sv}",
				                       "address",
				                       g_variant_new_string (nm_utils_inet6_ntop (&address->address, sbuf)));
				g_variant_builder_add (&addr_builder, "{sv}",
				                       "prefix",
				                       g_variant_new_uint32 (address->plen));
				if (   !IN6_IS_ADDR_UNSPECIFIED (&address->peer_address)
				    && !IN6_ARE_ADDR_EQUAL (&address->peer_address, &address->address)) {
					g_variant_builder_add (&addr_builder, "{sv}",
					                       "peer",
					                       g_variant_new_string (nm_utils_inet6_ntop (&address->peer_address, sbuf)));
				}

				g_variant_builder_add (&builder_data, "a{sv}", &addr_builder);

				g_variant_builder_add (&builder_legacy, "(@ayu@ay)",
				                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
				                                                  &address->address, 16, 1),
				                       address->plen,
				                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
				                                                  (   i == 0
				                                                   && priv->best_default_route)
				                                                     ? &NMP_OBJECT_CAST_IP6_ROUTE (priv->best_default_route)->gateway
				                                                     : &in6addr_any,
				                                                  16, 1));
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
		g_variant_builder_init (&builder_legacy, G_VARIANT_TYPE ("a(ayuayu)"));

		nm_ip_config_iter_ip6_route_for_each (&ipconf_iter, self, &route) {
			GVariantBuilder route_builder;

			nm_assert (_route_valid (route));

			g_variant_builder_init (&route_builder, G_VARIANT_TYPE ("a{sv}"));
			g_variant_builder_add (&route_builder, "{sv}",
			                       "dest",
			                       g_variant_new_string (nm_utils_inet6_ntop (&route->network, sbuf)));
			g_variant_builder_add (&route_builder, "{sv}",
			                       "prefix",
			                       g_variant_new_uint32 (route->plen));
			if (!IN6_IS_ADDR_UNSPECIFIED (&route->gateway)) {
				g_variant_builder_add (&route_builder, "{sv}",
				                       "next-hop",
				                       g_variant_new_string (nm_utils_inet6_ntop (&route->gateway, sbuf)));
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

			/* legacy versions of nm_ip6_route_set_prefix() in libnm-util assert that the
			 * plen is positive. Skip the default routes not to break older clients. */
			if (   nm_platform_route_table_is_main (route->table_coerced)
			    && !NM_PLATFORM_IP_ROUTE_IS_DEFAULT (route)) {
				g_variant_builder_add (&builder_legacy, "(@ayu@ayu)",
				                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
				                                                  &route->network, 16, 1),
				                       (guint32) route->plen,
				                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
				                                                  &route->gateway, 16, 1),
				                       (guint32) route->metric);
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
			g_value_take_string (value,
			                     nm_utils_inet6_ntop_dup (&NMP_OBJECT_CAST_IP6_ROUTE (priv->best_default_route)->gateway));
		} else
			g_value_set_string (value, NULL);
		break;
	case PROP_NAMESERVERS:
		nameservers_to_gvalue (priv->nameservers, value);
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
	NMIP6Config *self = NM_IP6_CONFIG (object);
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

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
nm_ip6_config_init (NMIP6Config *self)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	nm_ip_config_dedup_multi_idx_type_init ((NMIPConfigDedupMultiIdxType *) &priv->idx_ip6_addresses,
	                                        NMP_OBJECT_TYPE_IP6_ADDRESS);
	nm_ip_config_dedup_multi_idx_type_init ((NMIPConfigDedupMultiIdxType *) &priv->idx_ip6_routes,
	                                        NMP_OBJECT_TYPE_IP6_ROUTE);

	priv->nameservers = g_array_new (FALSE, TRUE, sizeof (struct in6_addr));
	priv->domains = g_ptr_array_new_with_free_func (g_free);
	priv->searches = g_ptr_array_new_with_free_func (g_free);
	priv->dns_options = g_ptr_array_new_with_free_func (g_free);
}

NMIP6Config *
nm_ip6_config_new (NMDedupMultiIndex *multi_idx, int ifindex)
{
	g_return_val_if_fail (ifindex >= -1, NULL);
	return (NMIP6Config *) g_object_new (NM_TYPE_IP6_CONFIG,
	                                     NM_IP6_CONFIG_MULTI_IDX, multi_idx,
	                                     NM_IP6_CONFIG_IFINDEX, ifindex,
	                                     NULL);
}

NMIP6Config *
nm_ip6_config_new_cloned (const NMIP6Config *src)
{
	NMIP6Config *new;

	g_return_val_if_fail (NM_IS_IP6_CONFIG (src), NULL);

	new = nm_ip6_config_new (nm_ip6_config_get_multi_idx (src),
	                         nm_ip6_config_get_ifindex (src));
	nm_ip6_config_replace (new, src, NULL);
	return new;
}

static void
finalize (GObject *object)
{
	NMIP6Config *self = NM_IP6_CONFIG (object);
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	nm_clear_nmp_object (&priv->best_default_route);

	nm_dedup_multi_index_remove_idx (priv->multi_idx, &priv->idx_ip6_addresses);
	nm_dedup_multi_index_remove_idx (priv->multi_idx, &priv->idx_ip6_routes);

	nm_clear_g_variant (&priv->address_data_variant);
	nm_clear_g_variant (&priv->addresses_variant);
	nm_clear_g_variant (&priv->route_data_variant);
	nm_clear_g_variant (&priv->routes_variant);

	g_array_unref (priv->nameservers);
	g_ptr_array_unref (priv->domains);
	g_ptr_array_unref (priv->searches);
	g_ptr_array_unref (priv->dns_options);

	G_OBJECT_CLASS (nm_ip6_config_parent_class)->finalize (object);

	nm_dedup_multi_index_unref (priv->multi_idx);
}

static const NMDBusInterfaceInfoExtended interface_info_ip6_config = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_IP6_CONFIG,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Addresses",   "a(ayuay)",  NM_IP6_CONFIG_ADDRESSES),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("AddressData", "aa{sv}",    NM_IP6_CONFIG_ADDRESS_DATA),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Gateway",     "s",         NM_IP6_CONFIG_GATEWAY),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Routes",      "a(ayuayu)", NM_IP6_CONFIG_ROUTES),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("RouteData",   "aa{sv}",    NM_IP6_CONFIG_ROUTE_DATA),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Nameservers", "aay",       NM_IP6_CONFIG_NAMESERVERS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Domains",     "as",        NM_IP6_CONFIG_DOMAINS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Searches",    "as",        NM_IP6_CONFIG_SEARCHES),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("DnsOptions",  "as",        NM_IP6_CONFIG_DNS_OPTIONS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("DnsPriority", "i",         NM_IP6_CONFIG_DNS_PRIORITY),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_ip6_config_class_init (NMIP6ConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (config_class);

	dbus_object_class->export_path = NM_DBUS_EXPORT_PATH_NUMBERED (NM_DBUS_PATH"/IP6Config");
	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_ip6_config);

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize = finalize;

	obj_properties[PROP_MULTI_IDX] =
	    g_param_spec_pointer (NM_IP6_CONFIG_MULTI_IDX, "", "",
	                            G_PARAM_WRITABLE
	                          | G_PARAM_CONSTRUCT_ONLY
	                          | G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_IFINDEX] =
	    g_param_spec_int (NM_IP6_CONFIG_IFINDEX, "", "",
	                      -1, G_MAXINT, -1,
	                      G_PARAM_READWRITE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ADDRESS_DATA] =
	    g_param_spec_variant (NM_IP6_CONFIG_ADDRESS_DATA, "", "",
	                          G_VARIANT_TYPE ("aa{sv}"),
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ADDRESSES] =
	    g_param_spec_variant (NM_IP6_CONFIG_ADDRESSES, "", "",
	                          G_VARIANT_TYPE ("a(ayuay)"),
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ROUTE_DATA] =
	    g_param_spec_variant (NM_IP6_CONFIG_ROUTE_DATA, "", "",
	                          G_VARIANT_TYPE ("aa{sv}"),
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ROUTES] =
	    g_param_spec_variant (NM_IP6_CONFIG_ROUTES, "", "",
	                          G_VARIANT_TYPE ("a(ayuayu)"),
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_GATEWAY] =
	    g_param_spec_string (NM_IP6_CONFIG_GATEWAY, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_NAMESERVERS] =
	    g_param_spec_variant (NM_IP6_CONFIG_NAMESERVERS, "", "",
	                          G_VARIANT_TYPE ("aay"),
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DOMAINS] =
	    g_param_spec_boxed (NM_IP6_CONFIG_DOMAINS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_SEARCHES] =
	    g_param_spec_boxed (NM_IP6_CONFIG_SEARCHES, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DNS_OPTIONS] =
	    g_param_spec_boxed (NM_IP6_CONFIG_DNS_OPTIONS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DNS_PRIORITY] =
	    g_param_spec_int (NM_IP6_CONFIG_DNS_PRIORITY, "", "",
	                      G_MININT32, G_MAXINT32, 0,
	                      G_PARAM_READABLE |
	                      G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
