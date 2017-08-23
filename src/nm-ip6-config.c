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
 * Copyright (C) 2005 - 2013 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-ip6-config.h"

#include <string.h>
#include <arpa/inet.h>

#include "nm-utils/nm-dedup-multi.h"

#include "nm-utils.h"
#include "platform/nmp-object.h"
#include "platform/nm-platform.h"
#include "platform/nm-platform-utils.h"
#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"
#include "nm-ip4-config.h"
#include "ndisc/nm-ndisc.h"

#include "introspection/org.freedesktop.NetworkManager.IP6Config.h"

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
	bool never_default:1;
	guint32 mss;
	int ifindex;
	int dns_priority;
	NMSettingIP6ConfigPrivacy privacy;
	gint64 route_metric;
	struct in6_addr gateway;
	GArray *nameservers;
	GPtrArray *domains;
	GPtrArray *searches;
	GPtrArray *dns_options;
	GVariant *address_data_variant;
	GVariant *addresses_variant;
	GVariant *route_data_variant;
	GVariant *routes_variant;
	NMDedupMultiIndex *multi_idx;
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
	NMExportedObject parent;
	NMIP6ConfigPrivate _priv;
};

struct _NMIP6ConfigClass {
	NMExportedObjectClass parent;
};

G_DEFINE_TYPE (NMIP6Config, nm_ip6_config, NM_TYPE_EXPORTED_OBJECT)

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
static void _add_route (NMIP6Config *self, const NMPObject *obj_new, const NMPlatformIP6Route *new);

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

static void
_notify_addresses (NMIP6Config *self)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	nm_clear_g_variant (&priv->address_data_variant);
	nm_clear_g_variant (&priv->addresses_variant);
	_notify (self, PROP_ADDRESS_DATA);
	_notify (self, PROP_ADDRESSES);
}

static void
_notify_routes (NMIP6Config *self)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	nm_clear_g_variant (&priv->route_data_variant);
	nm_clear_g_variant (&priv->routes_variant);
	_notify (self, PROP_ROUTE_DATA);
	_notify (self, PROP_ROUTES);
}

/*****************************************************************************/

/**
 * nm_ip6_config_capture_resolv_conf():
 * @nameservers: array of struct in6_addr
 * @rc_contents: the contents of a resolv.conf or %NULL to read /etc/resolv.conf
 *
 * Reads all resolv.conf IPv6 nameservers and adds them to @nameservers.
 *
 * Returns: %TRUE if nameservers were added, %FALSE if @nameservers is unchanged
 */
gboolean
nm_ip6_config_capture_resolv_conf (GArray *nameservers,
                                   GPtrArray *dns_options,
                                   const char *rc_contents)
{
	GPtrArray *read_ns, *read_options;
	guint i, j;
	gboolean changed = FALSE;

	g_return_val_if_fail (nameservers != NULL, FALSE);

	read_ns = nm_utils_read_resolv_conf_nameservers (rc_contents);
	if (!read_ns)
		return FALSE;

	for (i = 0; i < read_ns->len; i++) {
		const char *s = g_ptr_array_index (read_ns, i);
		struct in6_addr ns = IN6ADDR_ANY_INIT;

		if (!inet_pton (AF_INET6, s, (void *) &ns) || IN6_IS_ADDR_UNSPECIFIED (&ns))
			continue;

		/* Ignore duplicates */
		for (j = 0; j < nameservers->len; j++) {
			struct in6_addr *t = &g_array_index (nameservers, struct in6_addr, j);

			if (IN6_ARE_ADDR_EQUAL (t, &ns))
				break;
		}

		if (j == nameservers->len) {
			g_array_append_val (nameservers, ns);
			changed = TRUE;
		}
	}
	g_ptr_array_unref (read_ns);

	if (dns_options) {
		read_options = nm_utils_read_resolv_conf_dns_options (rc_contents);
		if (!read_options)
			return changed;

		for (i = 0; i < read_options->len; i++) {
			const char *s = g_ptr_array_index (read_options, i);

			if (_nm_utils_dns_option_validate (s, NULL, NULL, TRUE, _nm_utils_dns_option_descs) &&
				_nm_utils_dns_option_find_idx (dns_options, s) < 0) {
				g_ptr_array_add (dns_options, g_strdup (s));
				changed = TRUE;
			}
		}
		g_ptr_array_unref (read_options);
	}

	return changed;
}

static gint
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
	gint p1, p2, c;
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
_nmtst_nm_ip6_config_addresses_sort (NMIP6Config *self)
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
nm_ip6_config_capture (NMDedupMultiIndex *multi_idx, NMPlatform *platform, int ifindex, gboolean capture_resolv_conf, NMSettingIP6ConfigPrivacy use_temporary)
{
	NMIP6Config *self;
	NMIP6ConfigPrivate *priv;
	guint32 lowest_metric = G_MAXUINT32;
	struct in6_addr old_gateway = IN6ADDR_ANY_INIT;
	gboolean has_gateway;
	const NMDedupMultiHeadEntry *head_entry;
	NMDedupMultiIter iter;
	const NMPObject *plobj = NULL;
	gboolean notify_nameservers = FALSE;
	gboolean has_addresses = FALSE;

	nm_assert (ifindex > 0);

	/* Slaves have no IP configuration */
	if (nm_platform_link_get_master (platform, ifindex) > 0)
		return NULL;

	self = nm_ip6_config_new (multi_idx, ifindex);
	priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	head_entry = nm_platform_lookup_addrroute (platform,
	                                           NMP_OBJECT_TYPE_IP6_ADDRESS,
	                                           ifindex);
	if (head_entry) {
		nmp_cache_iter_for_each (&iter, head_entry, &plobj) {
			if (!nm_dedup_multi_index_add (priv->multi_idx,
			                               &priv->idx_ip6_addresses,
			                               plobj,
			                               NM_DEDUP_MULTI_IDX_MODE_APPEND,
			                               NULL,
			                               NULL))
				nm_assert_not_reached ();
			has_addresses = TRUE;
		}
		head_entry = nm_ip6_config_lookup_addresses (self);
		nm_assert (head_entry);
		nm_dedup_multi_head_entry_sort (head_entry,
		                                sort_captured_addresses,
		                                GINT_TO_POINTER (use_temporary));
	}

	head_entry = nm_platform_lookup_addrroute (platform,
	                                           NMP_OBJECT_TYPE_IP6_ROUTE,
	                                           ifindex);

	/* Extract gateway from default route */
	old_gateway = priv->gateway;

	lowest_metric = G_MAXUINT32;
	has_gateway = FALSE;
	nmp_cache_iter_for_each (&iter, head_entry, &plobj) {
		const NMPlatformIP6Route *route = NMP_OBJECT_CAST_IP6_ROUTE (plobj);

		if (   NM_PLATFORM_IP_ROUTE_IS_DEFAULT (route)
		    && route->rt_source != NM_IP_CONFIG_SOURCE_RTPROT_KERNEL) {
			if (route->metric < lowest_metric) {
				priv->gateway = route->gateway;
				lowest_metric = route->metric;
			}
			has_gateway = TRUE;
		}
	}

	/* we detect the route metric based on the default route. All non-default
	 * routes have their route metrics explicitly set. */
	priv->route_metric = has_gateway ? (gint64) lowest_metric : (gint64) -1;

	nmp_cache_iter_for_each (&iter, head_entry, &plobj) {
		const NMPlatformIP6Route *route = NMP_OBJECT_CAST_IP6_ROUTE (plobj);

		if (route->rt_source == NM_IP_CONFIG_SOURCE_RTPROT_KERNEL)
			continue;
		if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT (route))
			continue;

		_add_route (self, plobj, NULL);
	}

	/* If the interface has the default route, and has IPv6 addresses, capture
	 * nameservers from /etc/resolv.conf.
	 */
	if (has_addresses && has_gateway && capture_resolv_conf)
		notify_nameservers = nm_ip6_config_capture_resolv_conf (priv->nameservers,
		                                                        priv->dns_options,
		                                                        NULL);

	/* actually, nobody should be connected to the signal, just to be sure, notify */
	if (notify_nameservers)
		_notify (self, PROP_NAMESERVERS);
	_notify_addresses (self);
	_notify_routes (self);
	if (!IN6_ARE_ADDR_EQUAL (&priv->gateway, &old_gateway))
		_notify (self, PROP_GATEWAY);

	return self;
}

gboolean
nm_ip6_config_commit (const NMIP6Config *self,
                      NMPlatform *platform)
{
	gs_unref_ptrarray GPtrArray *addresses = NULL;
	gs_unref_ptrarray GPtrArray *routes = NULL;
	int ifindex;
	gboolean success = TRUE;

	g_return_val_if_fail (NM_IS_IP6_CONFIG (self), FALSE);

	ifindex = nm_ip6_config_get_ifindex (self);
	g_return_val_if_fail (ifindex > 0, FALSE);

	addresses = nm_dedup_multi_objs_to_ptr_array_head (nm_ip6_config_lookup_addresses (self),
	                                                   NULL, NULL);
	routes = nm_dedup_multi_objs_to_ptr_array_head (nm_ip6_config_lookup_routes (self),
	                                                NULL, NULL);
	nm_platform_ip6_address_sync (platform, ifindex, addresses, TRUE);

	if (!nm_platform_ip_route_sync (platform,
	                                AF_INET6,
	                                ifindex,
	                                routes,
	                                nm_platform_lookup_predicate_routes_main_skip_rtprot_kernel,
	                                NULL))
		success = FALSE;

	return success;
}

static void
merge_route_attributes (NMIPRoute *s_route, NMPlatformIP6Route *r)
{
	GVariant *variant;
	struct in6_addr addr;

#define GET_ATTR(name, field, variant_type, type) \
	variant = nm_ip_route_get_attribute (s_route, name); \
	if (variant && g_variant_is_of_type (variant, G_VARIANT_TYPE_ ## variant_type)) \
		r->field = g_variant_get_ ## type (variant);

	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_WINDOW,         window,         UINT32,   uint32);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_CWND,           cwnd,           UINT32,   uint32);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_INITCWND,       initcwnd,       UINT32,   uint32);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_INITRWND,       initrwnd,       UINT32,   uint32);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_MTU,            mtu,            UINT32,   uint32);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_LOCK_WINDOW,    lock_window,    BOOLEAN,  boolean);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_LOCK_CWND,      lock_cwnd,      BOOLEAN,  boolean);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_LOCK_INITCWND,  lock_initcwnd,  BOOLEAN,  boolean);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_LOCK_INITRWND,  lock_initrwnd,  BOOLEAN,  boolean);
	GET_ATTR (NM_IP_ROUTE_ATTRIBUTE_LOCK_MTU,       lock_mtu,       BOOLEAN,  boolean);


	if (   (variant = nm_ip_route_get_attribute (s_route, NM_IP_ROUTE_ATTRIBUTE_SRC))
	    && g_variant_is_of_type (variant, G_VARIANT_TYPE_STRING)) {
		if (inet_pton (AF_INET6, g_variant_get_string (variant, NULL), &addr) == 1)
			r->pref_src = addr;
	}

	if (   (variant = nm_ip_route_get_attribute (s_route, NM_IP_ROUTE_ATTRIBUTE_FROM))
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
			r->src = addr;
			r->src_plen = plen;
		}
	}
#undef GET_ATTR
}

void
nm_ip6_config_merge_setting (NMIP6Config *self, NMSettingIPConfig *setting, guint32 default_route_metric)
{
	NMIP6ConfigPrivate *priv;
	guint naddresses, nroutes, nnameservers, nsearches;
	const char *gateway_str;
	int i, priority;

	if (!setting)
		return;

	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	naddresses = nm_setting_ip_config_get_num_addresses (setting);
	nroutes = nm_setting_ip_config_get_num_routes (setting);
	nnameservers = nm_setting_ip_config_get_num_dns (setting);
	nsearches = nm_setting_ip_config_get_num_dns_searches (setting);

	g_object_freeze_notify (G_OBJECT (self));

	/* Gateway */
	if (nm_setting_ip_config_get_never_default (setting))
		nm_ip6_config_set_never_default (self, TRUE);
	else if (nm_setting_ip_config_get_ignore_auto_routes (setting))
		nm_ip6_config_set_never_default (self, FALSE);
	gateway_str = nm_setting_ip_config_get_gateway (setting);
	if (gateway_str) {
		struct in6_addr gateway;

		inet_pton (AF_INET6, gateway_str, &gateway);
		nm_ip6_config_set_gateway (self, &gateway);
	}

	if (priv->route_metric  == -1)
		priv->route_metric = nm_setting_ip_config_get_route_metric (setting);

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
	if (nm_setting_ip_config_get_ignore_auto_routes (setting))
		nm_ip6_config_reset_routes (self);
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
			route.metric = default_route_metric;
		else
			route.metric = nm_ip_route_get_metric (s_route);
		route.rt_source = NM_IP_CONFIG_SOURCE_USER;

		nm_utils_ip6_address_clear_host_address (&route.network, &route.network, route.plen);

		merge_route_attributes (s_route, &route);
		_add_route (self, NULL, &route);
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
	NMSettingIPConfig *s_ip6;
	const struct in6_addr *gateway;
	guint nnameservers, nsearches, noptions;
	const char *method = NULL;
	int i;
	gint64 route_metric;
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

	gateway = nm_ip6_config_get_gateway (self);
	nnameservers = nm_ip6_config_get_num_nameservers (self);
	nsearches = nm_ip6_config_get_num_searches (self);
	noptions = nm_ip6_config_get_num_dns_options (self);
	route_metric = nm_ip6_config_get_route_metric (self);

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
	if (   gateway
	    && nm_setting_ip_config_get_num_addresses (s_ip6) > 0) {
		g_object_set (s_ip6,
		              NM_SETTING_IP_CONFIG_GATEWAY, nm_utils_inet6_ntop (gateway, NULL),
		              NULL);
	}

	/* Use 'ignore' if the method wasn't previously set */
	if (!method)
		method = NM_SETTING_IP6_CONFIG_METHOD_IGNORE;

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, method,
	              NM_SETTING_IP_CONFIG_ROUTE_METRIC, (gint64) route_metric,
	              NULL);

	/* Routes */
	nm_ip_config_iter_ip6_route_for_each (&ipconf_iter, self, &route) {
		NMIPRoute *s_route;

		/* Ignore link-local route. */
		if (IN6_IS_ADDR_LINKLOCAL (&route->network))
			continue;

		/* Ignore default route. */
		if (!route->plen)
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

		nm_setting_ip_config_add_dns (s_ip6, nm_utils_inet6_ntop (nameserver, NULL));
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
nm_ip6_config_merge (NMIP6Config *dst, const NMIP6Config *src, NMIPConfigMergeFlags merge_flags)
{
	NMIP6ConfigPrivate *dst_priv;
	const NMIP6ConfigPrivate *src_priv;
	guint32 i;
	NMDedupMultiIter ipconf_iter;
	const NMPlatformIP6Address *address = NULL;

	g_return_if_fail (src != NULL);
	g_return_if_fail (dst != NULL);

	dst_priv = NM_IP6_CONFIG_GET_PRIVATE (dst);
	src_priv = NM_IP6_CONFIG_GET_PRIVATE (src);

	g_object_freeze_notify (G_OBJECT (dst));

	/* addresses */
	nm_ip_config_iter_ip6_address_for_each (&ipconf_iter, src, &address)
		_add_address (dst, NMP_OBJECT_UP_CAST (address), NULL);

	/* nameservers */
	if (!NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_DNS)) {
		for (i = 0; i < nm_ip6_config_get_num_nameservers (src); i++)
			nm_ip6_config_add_nameserver (dst, nm_ip6_config_get_nameserver (src, i));
	}

	/* default gateway */
	if (nm_ip6_config_get_gateway (src))
		nm_ip6_config_set_gateway (dst, nm_ip6_config_get_gateway (src));

	/* routes */
	if (!NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_ROUTES)) {
		const NMPlatformIP6Route *route;

		nm_ip_config_iter_ip6_route_for_each (&ipconf_iter, src, &route)
			_add_route (dst, NMP_OBJECT_UP_CAST (route), NULL);
	}

	if (dst_priv->route_metric == -1)
		dst_priv->route_metric = src_priv->route_metric;
	else if (src_priv->route_metric != -1)
		dst_priv->route_metric = MIN (dst_priv->route_metric, src_priv->route_metric);

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

	if (nm_ip6_config_get_mss (src))
		nm_ip6_config_set_mss (dst, nm_ip6_config_get_mss (src));

	/* DNS priority */
	if (nm_ip6_config_get_dns_priority (src))
		nm_ip6_config_set_dns_priority (dst, nm_ip6_config_get_dns_priority (src));

	g_object_thaw_notify (G_OBJECT (dst));
}

gboolean
nm_ip6_config_destination_is_direct (const NMIP6Config *self, const struct in6_addr *network, guint8 plen)
{
	const NMPlatformIP6Address *item;
	NMDedupMultiIter iter;

	nm_assert (network);
	nm_assert (plen <= 128);

	nm_ip_config_iter_ip6_address_for_each (&iter, self, &item) {
		if (   item->plen <= plen
		    && !NM_FLAGS_HAS (item->n_ifa_flags, IFA_F_NOPREFIXROUTE)
		    && nm_utils_ip6_address_same_prefix (&item->address, network, item->plen))
			return TRUE;
	}

	return FALSE;
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
 *
 * Removes everything in @src from @dst.
 */
void
nm_ip6_config_subtract (NMIP6Config *dst, const NMIP6Config *src)
{
	NMIP6ConfigPrivate *priv_dst;
	guint i;
	gint idx;
	const NMPlatformIP6Address *a;
	const NMPlatformIP6Route *r;
	NMDedupMultiIter ipconf_iter;
	const struct in6_addr *dst_tmp, *src_tmp;
	gboolean changed;

	g_return_if_fail (src != NULL);
	g_return_if_fail (dst != NULL);

	priv_dst = NM_IP6_CONFIG_GET_PRIVATE (dst);

	g_object_freeze_notify (G_OBJECT (dst));

	/* addresses */
	changed = FALSE;
	nm_ip_config_iter_ip6_address_for_each (&ipconf_iter, src, &a) {
		if (nm_dedup_multi_index_remove_obj (priv_dst->multi_idx,
		                                     &priv_dst->idx_ip6_addresses,
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

	/* default gateway */
	src_tmp = nm_ip6_config_get_gateway (src);
	dst_tmp = nm_ip6_config_get_gateway (dst);
	if (src_tmp && dst_tmp && IN6_ARE_ADDR_EQUAL (src_tmp, dst_tmp))
		nm_ip6_config_set_gateway (dst, NULL);

	if (!nm_ip6_config_get_num_addresses (dst))
		nm_ip6_config_set_gateway (dst, NULL);

	/* ignore route_metric */

	/* routes */
	changed = FALSE;
	nm_ip_config_iter_ip6_route_for_each (&ipconf_iter, src, &r) {
		if (nm_dedup_multi_index_remove_obj (priv_dst->multi_idx,
		                                     &priv_dst->idx_ip6_routes,
		                                     NMP_OBJECT_UP_CAST (r),
		                                     NULL))
			changed = TRUE;
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

	if (nm_ip6_config_get_mss (src) == nm_ip6_config_get_mss (dst))
		nm_ip6_config_set_mss (dst, 0);

	/* DNS priority */
	if (nm_ip6_config_get_dns_priority (src) == nm_ip6_config_get_dns_priority (dst))
		nm_ip6_config_set_dns_priority (dst, 0);

	g_object_thaw_notify (G_OBJECT (dst));
}

void
nm_ip6_config_intersect (NMIP6Config *dst, const NMIP6Config *src)
{
	NMIP6ConfigPrivate *priv_dst;
	const NMIP6ConfigPrivate *priv_src;
	const struct in6_addr *dst_tmp, *src_tmp;
	NMDedupMultiIter ipconf_iter;
	const NMPlatformIP6Address *a;
	const NMPlatformIP6Route *r;
	gboolean changed;

	g_return_if_fail (src);
	g_return_if_fail (dst);

	priv_dst = NM_IP6_CONFIG_GET_PRIVATE (dst);
	priv_src = NM_IP6_CONFIG_GET_PRIVATE (src);

	g_object_freeze_notify (G_OBJECT (dst));

	/* addresses */
	changed = FALSE;
	nm_ip_config_iter_ip6_address_for_each (&ipconf_iter, dst, &a) {
		if (nm_dedup_multi_index_lookup_obj (priv_src->multi_idx,
		                                     &priv_src->idx_ip6_addresses,
		                                     NMP_OBJECT_UP_CAST (a)))
			continue;

		if (nm_dedup_multi_index_remove_entry (priv_dst->multi_idx,
		                                       ipconf_iter.current) != 1)
			nm_assert_not_reached ();
		changed = TRUE;
	}
	if (changed)
		_notify_addresses (dst);

	/* ignore route_metric */
	/* ignore nameservers */

	/* default gateway */
	dst_tmp = nm_ip6_config_get_gateway (dst);
	if (dst_tmp) {
		src_tmp = nm_ip6_config_get_gateway (src);
		if (   !nm_ip6_config_get_num_addresses (dst)
		    || !src_tmp
		    || !IN6_ARE_ADDR_EQUAL (src_tmp, dst_tmp))
			nm_ip6_config_set_gateway (dst, NULL);
	}

	/* routes */
	changed = FALSE;
	nm_ip_config_iter_ip6_route_for_each (&ipconf_iter, dst, &r) {
		if (nm_dedup_multi_index_lookup_obj (priv_src->multi_idx,
		                                     &priv_src->idx_ip6_routes,
		                                     NMP_OBJECT_UP_CAST (r)))
			continue;

		if (nm_dedup_multi_index_remove_entry (priv_dst->multi_idx,
		                                       ipconf_iter.current) != 1)
			nm_assert_not_reached ();
		changed = TRUE;
	}
	if (changed)
		_notify_routes (dst);

	/* ignore domains */
	/* ignore dns searches */
	/* ignome dns options */

	g_object_thaw_notify (G_OBJECT (dst));
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

	/* never_default */
	if (src_priv->never_default != dst_priv->never_default) {
		dst_priv->never_default = src_priv->never_default;
		has_minor_changes = TRUE;
	}

	/* default gateway */
	if (!IN6_ARE_ADDR_EQUAL (&src_priv->gateway, &dst_priv->gateway)) {
		nm_ip6_config_set_gateway (dst, &src_priv->gateway);
		has_relevant_changes = TRUE;
	}

	if (src_priv->route_metric != dst_priv->route_metric) {
		dst_priv->route_metric = src_priv->route_metric;
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
			if (   !nm_ip_config_obj_id_equal_ip6_address (r_src, r_dst)
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
			                       TRUE);
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
			if (   !nm_ip_config_obj_id_equal_ip6_route (r_src, r_dst)
			    || r_src->metric != r_dst->metric
			    || !IN6_ARE_ADDR_EQUAL (&r_src->gateway, &r_dst->gateway)) {
				has_relevant_changes = TRUE;
				break;
			}
		}
	}
	if (!are_equal) {
		has_minor_changes = TRUE;
		nm_dedup_multi_index_dirty_set_idx (dst_priv->multi_idx, &dst_priv->idx_ip6_routes);
		nm_dedup_multi_iter_for_each (&ipconf_iter_src, head_entry_src) {
			_nm_ip_config_add_obj (dst_priv->multi_idx,
			                       &dst_priv->idx_ip6_routes_,
			                       dst_priv->ifindex,
			                       ipconf_iter_src.current->obj,
			                       NULL,
			                       FALSE,
			                       TRUE);
		}
		nm_dedup_multi_index_dirty_remove_idx (dst_priv->multi_idx, &dst_priv->idx_ip6_routes, FALSE);
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

	/* mss */
	if (src_priv->mss != dst_priv->mss) {
		nm_ip6_config_set_mss (dst, src_priv->mss);
		has_minor_changes = TRUE;
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

void
nm_ip6_config_dump (const NMIP6Config *self, const char *detail)
{
	const struct in6_addr *tmp;
	guint32 i;
	const char *str;
	NMDedupMultiIter ipconf_iter;
	const NMPlatformIP6Address *address;
	const NMPlatformIP6Route *route;

	g_return_if_fail (self != NULL);

	g_message ("--------- NMIP6Config %p (%s)", self, detail);

	str = nm_exported_object_get_path (NM_EXPORTED_OBJECT (self));
	if (str)
		g_message ("   path: %s", str);

	/* addresses */
	nm_ip_config_iter_ip6_address_for_each (&ipconf_iter, self, &address)
		g_message ("      a: %s", nm_platform_ip6_address_to_string (address, NULL, 0));

	/* default gateway */
	tmp = nm_ip6_config_get_gateway (self);
	if (tmp)
		g_message ("     gw: %s", nm_utils_inet6_ntop (tmp, NULL));

	/* nameservers */
	for (i = 0; i < nm_ip6_config_get_num_nameservers (self); i++) {
		tmp = nm_ip6_config_get_nameserver (self, i);
		g_message ("     ns: %s", nm_utils_inet6_ntop (tmp, NULL));
	}

	/* routes */
	nm_ip_config_iter_ip6_route_for_each (&ipconf_iter, self, &route)
		g_message ("     rt: %s", nm_platform_ip6_route_to_string (route, NULL, 0));

	/* domains */
	for (i = 0; i < nm_ip6_config_get_num_domains (self); i++)
		g_message (" domain: %s", nm_ip6_config_get_domain (self, i));

	/* dns searches */
	for (i = 0; i < nm_ip6_config_get_num_searches (self); i++)
		g_message (" search: %s", nm_ip6_config_get_search (self, i));

	/* dns options */
	for (i = 0; i < nm_ip6_config_get_num_dns_options (self); i++)
		g_message (" dnsopt: %s", nm_ip6_config_get_dns_option (self, i));

	g_message (" dnspri: %d", nm_ip6_config_get_dns_priority (self));

	g_message ("    mss: %"G_GUINT32_FORMAT, nm_ip6_config_get_mss (self));
	g_message (" n-dflt: %d", nm_ip6_config_get_never_default (self));
}

/*****************************************************************************/

void
nm_ip6_config_set_never_default (NMIP6Config *self, gboolean never_default)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	priv->never_default = never_default;
}

gboolean
nm_ip6_config_get_never_default (const NMIP6Config *self)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	return priv->never_default;
}

void
nm_ip6_config_set_gateway (NMIP6Config *self, const struct in6_addr *gateway)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	if (gateway) {
		if (IN6_ARE_ADDR_EQUAL (&priv->gateway, gateway))
			return;
		priv->gateway = *gateway;
	} else {
		if (IN6_IS_ADDR_UNSPECIFIED (&priv->gateway))
			return;
		memset (&priv->gateway, 0, sizeof (priv->gateway));
	}
	_notify (self, PROP_GATEWAY);
}

const struct in6_addr *
nm_ip6_config_get_gateway (const NMIP6Config *self)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	return IN6_IS_ADDR_UNSPECIFIED (&priv->gateway) ? NULL : &priv->gateway;
}

gint64
nm_ip6_config_get_route_metric (const NMIP6Config *self)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	return priv->route_metric;
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
		                           TRUE))
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
	                           FALSE))
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
	g_return_if_fail (new->plen > 0 && new->plen <= 128);
	g_return_if_fail (NM_IP6_CONFIG_GET_PRIVATE (self)->ifindex > 0);

	_add_address (self, NULL, new);
}

void
_nmtst_nm_ip6_config_del_address (NMIP6Config *self, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	const NMPlatformIP6Address *a;

	a = _nmtst_nm_ip6_config_get_address (self, i);
	g_return_if_fail (a);

	if (nm_dedup_multi_index_remove_obj (priv->multi_idx,
	                                     &priv->idx_ip6_addresses,
	                                     NMP_OBJECT_UP_CAST (a),
	                                     NULL) != 1)
		g_return_if_reached ();
	_notify_addresses (self);
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
_nmtst_nm_ip6_config_get_address (const NMIP6Config *self, guint i)
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
nm_ip6_config_get_address_first_nontentative (const NMIP6Config *self, gboolean linklocal)
{
	const NMIP6ConfigPrivate *priv;
	const NMPlatformIP6Address *addr;
	NMDedupMultiIter iter;

	g_return_val_if_fail (NM_IS_IP6_CONFIG (self), NULL);

	priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	linklocal = !!linklocal;

	nm_ip_config_iter_ip6_address_for_each (&iter, self, &addr) {
		if (   ((!!IN6_IS_ADDR_LINKLOCAL (&addr->address)) == linklocal)
		    && !(addr->n_ifa_flags & IFA_F_TENTATIVE))
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

void
nm_ip6_config_reset_routes_ndisc (NMIP6Config *self,
                                  const NMNDiscRoute *routes,
                                  guint routes_n,
                                  guint32 metric)
{
	NMIP6ConfigPrivate *priv;
	guint i;
	gboolean changed = FALSE;

	g_return_if_fail (NM_IS_IP6_CONFIG (self));

	priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	g_return_if_fail (priv->ifindex > 0);

	nm_dedup_multi_index_dirty_set_idx (priv->multi_idx, &priv->idx_ip6_routes);

	for (i = 0; i < routes_n; i++) {
		const NMNDiscRoute *ndisc_route = &routes[i];
		NMPObject obj;
		NMPlatformIP6Route *r;

		nmp_object_stackinit (&obj, NMP_OBJECT_TYPE_IP6_ROUTE, NULL);
		r = NMP_OBJECT_CAST_IP6_ROUTE (&obj);
		r->ifindex    = priv->ifindex;
		r->network    = ndisc_route->network;
		r->plen       = ndisc_route->plen;
		r->gateway    = ndisc_route->gateway;
		r->rt_source  = NM_IP_CONFIG_SOURCE_NDISC;
		r->metric     = metric;

		if (_nm_ip_config_add_obj (priv->multi_idx,
		                           &priv->idx_ip6_routes_,
		                           priv->ifindex,
		                           &obj,
		                           NULL,
		                           FALSE,
		                           TRUE))
			changed = TRUE;
	}

	if (nm_dedup_multi_index_dirty_remove_idx (priv->multi_idx, &priv->idx_ip6_routes, FALSE) > 0)
		changed = TRUE;

	if (changed)
		_notify_routes (self);
}

void
nm_ip6_config_reset_routes (NMIP6Config *self)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	if (nm_dedup_multi_index_remove_idx (priv->multi_idx,
	                                     &priv->idx_ip6_routes) > 0)
		_notify_routes (self);
}

static void
_add_route (NMIP6Config *self, const NMPObject *obj_new, const NMPlatformIP6Route *new)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	nm_assert ((!new) != (!obj_new));
	nm_assert (!new || _route_valid (new));
	nm_assert (!obj_new || _route_valid (NMP_OBJECT_CAST_IP6_ROUTE (obj_new)));

	if (_nm_ip_config_add_obj (priv->multi_idx,
	                           &priv->idx_ip6_routes_,
	                           priv->ifindex,
	                           obj_new,
	                           (const NMPlatformObject *) new,
	                           TRUE,
	                           FALSE))
		_notify_routes (self);
}

/**
 * nm_ip6_config_add_route:
 * @self: the #NMIP6Config
 * @new: the new route to add to @self
 *
 * Adds the new route to @self.  If a route with the same basic properties
 * (network, prefix) already exists in @self, it is overwritten including the
 * gateway and metric of @new.  The source is also overwritten by the source
 * from @new if that source is higher priority.
 */
void
nm_ip6_config_add_route (NMIP6Config *self, const NMPlatformIP6Route *new)
{
	g_return_if_fail (self);
	g_return_if_fail (new);
	g_return_if_fail (new->plen > 0 && new->plen <= 128);
	g_return_if_fail (NM_IP6_CONFIG_GET_PRIVATE (self)->ifindex > 0);

	_add_route (self, NULL, new);
}

void
_nmtst_ip6_config_del_route (NMIP6Config *self, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	const NMPlatformIP6Route *r;

	r = _nmtst_ip6_config_get_route (self, i);
	g_return_if_fail (r);

	if (nm_dedup_multi_index_remove_obj (priv->multi_idx,
	                                     &priv->idx_ip6_routes,
	                                     NMP_OBJECT_UP_CAST (r),
	                                     NULL) != 1)
		g_return_if_reached ();
	_notify_routes (self);
}

guint
nm_ip6_config_get_num_routes (const NMIP6Config *self)
{
	const NMDedupMultiHeadEntry *head_entry;

	head_entry = nm_ip6_config_lookup_routes (self);
	nm_assert ((head_entry ? head_entry->len : 0) == c_list_length (&head_entry->lst_entries_head));
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
nm_ip6_config_get_direct_route_for_host (const NMIP6Config *self, const struct in6_addr *host)
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
	int i;

	g_return_if_fail (domain != NULL);
	g_return_if_fail (domain[0] != '\0');

	for (i = 0; i < priv->domains->len; i++)
		if (!g_strcmp0 (g_ptr_array_index (priv->domains, i), domain))
			return;

	g_ptr_array_add (priv->domains, g_strdup (domain));
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
nm_ip6_config_add_search (NMIP6Config *self, const char *new)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	char *search;
	size_t len;

	g_return_if_fail (new != NULL);
	g_return_if_fail (new[0] != '\0');

	search = g_strdup (new);

	/* Remove trailing dot as it has no effect */
	len = strlen (search);
	if (search[len - 1] == '.')
		search[len - 1] = 0;

	if (!search[0]) {
		g_free (search);
		return;
	}

	if (nm_utils_strv_find_first ((char **) priv->searches->pdata,
	                               priv->searches->len, search) >= 0) {
		g_free (search);
		return;
	}

	g_ptr_array_add (priv->searches, search);
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
nm_ip6_config_set_dns_priority (NMIP6Config *self, gint priority)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	if (priority != priv->dns_priority) {
		priv->dns_priority = priority;
		_notify (self, PROP_DNS_PRIORITY);
	}
}

gint
nm_ip6_config_get_dns_priority (const NMIP6Config *self)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	return priv->dns_priority;
}

/*****************************************************************************/

void
nm_ip6_config_set_mss (NMIP6Config *self, guint32 mss)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	priv->mss = mss;
}

guint32
nm_ip6_config_get_mss (const NMIP6Config *self)
{
	const NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	return priv->mss;
}

/*****************************************************************************/

static inline void
hash_u32 (GChecksum *sum, guint32 n)
{
	g_checksum_update (sum, (const guint8 *) &n, sizeof (n));
}

static inline void
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
		hash_in6addr (sum, nm_ip6_config_get_gateway (self));

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
	GChecksum *a_checksum = g_checksum_new (G_CHECKSUM_SHA1);
	GChecksum *b_checksum = g_checksum_new (G_CHECKSUM_SHA1);
	gsize a_len = g_checksum_type_get_length (G_CHECKSUM_SHA1);
	gsize b_len = g_checksum_type_get_length (G_CHECKSUM_SHA1);
	guchar a_data[a_len], b_data[b_len];
	gboolean equal;

	if (a)
		nm_ip6_config_hash (a, a_checksum, FALSE);
	if (b)
		nm_ip6_config_hash (b, b_checksum, FALSE);

	g_checksum_get_digest (a_checksum, a_data, &a_len);
	g_checksum_get_digest (b_checksum, b_data, &b_len);

	g_assert (a_len == b_len);
	equal = !memcmp (a_data, b_data, a_len);

	g_checksum_free (a_checksum);
	g_checksum_free (b_checksum);

	return equal;
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
				                       g_variant_new_string (nm_utils_inet6_ntop (&address->address, NULL)));
				g_variant_builder_add (&addr_builder, "{sv}",
				                       "prefix",
				                       g_variant_new_uint32 (address->plen));
				if (   !IN6_IS_ADDR_UNSPECIFIED (&address->peer_address)
				    && !IN6_ARE_ADDR_EQUAL (&address->peer_address, &address->address)) {
					g_variant_builder_add (&addr_builder, "{sv}",
					                       "peer",
					                       g_variant_new_string (nm_utils_inet6_ntop (&address->peer_address, NULL)));
				}

				g_variant_builder_add (&builder_data, "a{sv}", &addr_builder);

				g_variant_builder_add (&builder_legacy, "(@ayu@ay)",
				                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
				                                                  &address->address, 16, 1),
				                       address->plen,
				                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
				                                                  i == 0
				                                                    ? (nm_ip6_config_get_gateway (self) ?: &in6addr_any)
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
			                       g_variant_new_string (nm_utils_inet6_ntop (&route->network, NULL)));
			g_variant_builder_add (&route_builder, "{sv}",
			                       "prefix",
			                       g_variant_new_uint32 (route->plen));
			if (!IN6_IS_ADDR_UNSPECIFIED (&route->gateway)) {
				g_variant_builder_add (&route_builder, "{sv}",
				                       "next-hop",
				                       g_variant_new_string (nm_utils_inet6_ntop (&route->gateway, NULL)));
			}

			g_variant_builder_add (&route_builder, "{sv}",
			                       "metric",
			                       g_variant_new_uint32 (route->metric));

			g_variant_builder_add (&builder_data, "a{sv}", &route_builder);

			/* legacy versions of nm_ip6_route_set_prefix() in libnm-util assert that the
			 * plen is positive. Skip the default routes not to break older clients. */
			if (!NM_PLATFORM_IP_ROUTE_IS_DEFAULT (route)) {
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
		if (!IN6_IS_ADDR_UNSPECIFIED (&priv->gateway))
			g_value_set_string (value, nm_utils_inet6_ntop (&priv->gateway, NULL));
		else
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
	priv->route_metric = -1;
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

static void
nm_ip6_config_class_init (NMIP6ConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (config_class);

	exported_object_class->export_path = NM_EXPORT_PATH_NUMBERED (NM_DBUS_PATH"/IP6Config");

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

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (config_class),
	                                        NMDBUS_TYPE_IP6_CONFIG_SKELETON,
	                                        NULL);
}
