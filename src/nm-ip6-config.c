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

#include "config.h"

#include <string.h>
#include <arpa/inet.h>

#include "nm-glib.h"
#include "nm-ip6-config.h"

#include "nm-utils.h"
#include "nm-platform.h"
#include "nm-dbus-manager.h"
#include "nm-dbus-glib-types.h"
#include "nm-ip6-config-glue.h"
#include "nm-route-manager.h"
#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"

G_DEFINE_TYPE (NMIP6Config, nm_ip6_config, NM_TYPE_EXPORTED_OBJECT)

#define NM_IP6_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IP6_CONFIG, NMIP6ConfigPrivate))

typedef struct {
	char *path;

	gboolean never_default;
	struct in6_addr gateway;
	GArray *addresses;
	GArray *routes;
	GArray *nameservers;
	GPtrArray *domains;
	GPtrArray *searches;
	GPtrArray *dns_options;
	guint32 mss;
	int ifindex;
	gint64 route_metric;
} NMIP6ConfigPrivate;


enum {
	PROP_0,
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

	LAST_PROP
};
static GParamSpec *obj_properties[LAST_PROP] = { NULL, };
#define _NOTIFY(config, prop)    G_STMT_START { g_object_notify_by_pspec (G_OBJECT (config), obj_properties[prop]); } G_STMT_END


NMIP6Config *
nm_ip6_config_new (int ifindex)
{
	g_return_val_if_fail (ifindex >= -1, NULL);
	return (NMIP6Config *) g_object_new (NM_TYPE_IP6_CONFIG,
	                                     NM_IP6_CONFIG_IFINDEX, ifindex,
	                                     NULL);
}

void
nm_ip6_config_export (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	static guint32 counter = 0;

	if (!priv->path) {
		priv->path = g_strdup_printf (NM_DBUS_PATH "/IP6Config/%d", counter++);
		nm_dbus_manager_register_object (nm_dbus_manager_get (), priv->path, config);
	}
}

const char *
nm_ip6_config_get_dbus_path (const NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return priv->path;
}

int
nm_ip6_config_get_ifindex (const NMIP6Config *config)
{
	return NM_IP6_CONFIG_GET_PRIVATE (config)->ifindex;
}

/******************************************************************/

static gboolean
same_prefix (const struct in6_addr *address1, const struct in6_addr *address2, int plen)
{
	const guint8 *bytes1 = (const guint8 *) address1;
	const guint8 *bytes2 = (const guint8 *) address2;
	int nbytes = plen / 8;
	int nbits = plen % 8;
	int masked1 = bytes1[nbytes] >> (8 - nbits);
	int masked2 = bytes2[nbytes] >> (8 - nbits);

	if (nbytes && memcmp (bytes1, bytes2, nbytes))
		return FALSE;

	return masked1 == masked2;
}

/******************************************************************/

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

static gboolean
addresses_are_duplicate (const NMPlatformIP6Address *a, const NMPlatformIP6Address *b, gboolean consider_plen)
{
	return IN6_ARE_ADDR_EQUAL (&a->address, &b->address) && (!consider_plen || a->plen == b->plen);
}

static gboolean
routes_are_duplicate (const NMPlatformIP6Route *a, const NMPlatformIP6Route *b, gboolean consider_gateway_and_metric)
{
	return IN6_ARE_ADDR_EQUAL (&a->network, &b->network) && a->plen == b->plen &&
	       (   !consider_gateway_and_metric
	        || (   IN6_ARE_ADDR_EQUAL (&a->gateway, &b->gateway)
	            && nm_utils_ip6_route_metric_normalize (a->metric) == nm_utils_ip6_route_metric_normalize (b->metric)));
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

static gint
_addresses_sort_cmp (gconstpointer a, gconstpointer b, gpointer user_data)
{
	gint p1, p2, c;
	gboolean perm1, perm2, tent1, tent2;
	gboolean ipv6_privacy1, ipv6_privacy2;
	const NMPlatformIP6Address *a1 = a, *a2 = b;

	/* tentative addresses are always sorted back... */
	/* sort tentative addresses after non-tentative. */
	tent1 = (a1->flags & IFA_F_TENTATIVE);
	tent2 = (a2->flags & IFA_F_TENTATIVE);
	if (tent1 != tent2)
		return tent1 ? 1 : -1;

	/* Sort by address type. For example link local will
	 * be sorted *after* site local or global. */
	p1 = _addresses_sort_cmp_get_prio (&a1->address);
	p2 = _addresses_sort_cmp_get_prio (&a2->address);
	if (p1 != p2)
		return p1 > p2 ? -1 : 1;

	ipv6_privacy1 = !!(a1->flags & (IFA_F_MANAGETEMPADDR | IFA_F_TEMPORARY));
	ipv6_privacy2 = !!(a2->flags & (IFA_F_MANAGETEMPADDR | IFA_F_TEMPORARY));
	if (ipv6_privacy1 || ipv6_privacy2) {
		gboolean prefer_temp = ((NMSettingIP6ConfigPrivacy) GPOINTER_TO_INT (user_data)) == NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR;
		gboolean public1 = TRUE, public2 = TRUE;

		if (ipv6_privacy1) {
			if (a1->flags & IFA_F_TEMPORARY)
				public1 = prefer_temp;
			else
				public1 = !prefer_temp;
		}
		if (ipv6_privacy2) {
			if (a2->flags & IFA_F_TEMPORARY)
				public2 = prefer_temp;
			else
				public2 = !prefer_temp;
		}

		if (public1 != public2)
			return public1 ? -1 : 1;
	}

	/* Sort the addresses based on their source. */
	if (a1->source != a2->source)
		return a1->source > a2->source ? -1 : 1;

	/* sort permanent addresses before non-permanent. */
	perm1 = (a1->flags & IFA_F_PERMANENT);
	perm2 = (a2->flags & IFA_F_PERMANENT);
	if (perm1 != perm2)
		return perm1 ? -1 : 1;

	/* finally sort addresses lexically */
	c = memcmp (&a1->address, &a2->address, sizeof (a2->address));
	return c != 0 ? c : memcmp (a1, a2, sizeof (*a1));
}

gboolean
nm_ip6_config_addresses_sort (NMIP6Config *self, NMSettingIP6ConfigPrivacy use_temporary)
{
	NMIP6ConfigPrivate *priv;
	size_t data_len = 0;
	char *data_pre = NULL;
	gboolean changed;

	g_return_val_if_fail (NM_IS_IP6_CONFIG (self), FALSE);

	priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	if (priv->addresses->len > 1) {
		data_len = priv->addresses->len * g_array_get_element_size (priv->addresses);
		data_pre = g_new (char, data_len);
		memcpy (data_pre, priv->addresses->data, data_len);

		g_array_sort_with_data (priv->addresses, _addresses_sort_cmp, GINT_TO_POINTER (use_temporary));

		changed = memcmp (data_pre, priv->addresses->data, data_len) != 0;
		g_free (data_pre);

		if (changed) {
			_NOTIFY (self, PROP_ADDRESS_DATA);
			_NOTIFY (self, PROP_ADDRESSES);
			return TRUE;
		}
	}
	return FALSE;
}

NMIP6Config *
nm_ip6_config_capture (int ifindex, gboolean capture_resolv_conf, NMSettingIP6ConfigPrivacy use_temporary)
{
	NMIP6Config *config;
	NMIP6ConfigPrivate *priv;
	guint i;
	guint32 lowest_metric = G_MAXUINT32;
	struct in6_addr old_gateway = IN6ADDR_ANY_INIT;
	gboolean has_gateway = FALSE;
	gboolean notify_nameservers = FALSE;

	/* Slaves have no IP configuration */
	if (nm_platform_link_get_master (NM_PLATFORM_GET, ifindex) > 0)
		return NULL;

	config = nm_ip6_config_new (ifindex);
	priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	g_array_unref (priv->addresses);
	g_array_unref (priv->routes);

	priv->addresses = nm_platform_ip6_address_get_all (NM_PLATFORM_GET, ifindex);
	priv->routes = nm_platform_ip6_route_get_all (NM_PLATFORM_GET, ifindex, NM_PLATFORM_GET_ROUTE_FLAGS_WITH_DEFAULT | NM_PLATFORM_GET_ROUTE_FLAGS_WITH_NON_DEFAULT);

	/* Extract gateway from default route */
	old_gateway = priv->gateway;
	for (i = 0; i < priv->routes->len; ) {
		const NMPlatformIP6Route *route = &g_array_index (priv->routes, NMPlatformIP6Route, i);

		if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT (route)) {
			if (route->metric < lowest_metric) {
				priv->gateway = route->gateway;
				lowest_metric = route->metric;
			}
			has_gateway = TRUE;
			/* Remove the default route from the list */
			g_array_remove_index_fast (priv->routes, i);
			continue;
		}
		i++;
	}

	/* we detect the route metric based on the default route. All non-default
	 * routes have their route metrics explicitly set. */
	priv->route_metric = has_gateway ? (gint64) lowest_metric : (gint64) -1;

	/* If there is a host route to the gateway, ignore that route.  It is
	 * automatically added by NetworkManager when needed.
	 */
	if (has_gateway) {
		for (i = 0; i < priv->routes->len; i++) {
			const NMPlatformIP6Route *route = &g_array_index (priv->routes, NMPlatformIP6Route, i);

			if (   route->plen == 128
			    && IN6_ARE_ADDR_EQUAL (&route->network, &priv->gateway)
			    && IN6_IS_ADDR_UNSPECIFIED (&route->gateway)) {
				g_array_remove_index (priv->routes, i);
				i--;
			}
		}
	}

	/* If the interface has the default route, and has IPv6 addresses, capture
	 * nameservers from /etc/resolv.conf.
	 */
	if (priv->addresses->len && has_gateway && capture_resolv_conf)
		notify_nameservers = nm_ip6_config_capture_resolv_conf (priv->nameservers,
		                                                        priv->dns_options,
		                                                        NULL);

	g_array_sort_with_data (priv->addresses, _addresses_sort_cmp, GINT_TO_POINTER (use_temporary));

	/* actually, nobody should be connected to the signal, just to be sure, notify */
	if (notify_nameservers)
		_NOTIFY (config, PROP_NAMESERVERS);
	_NOTIFY (config, PROP_ADDRESS_DATA);
	_NOTIFY (config, PROP_ADDRESSES);
	_NOTIFY (config, PROP_ROUTE_DATA);
	_NOTIFY (config, PROP_ROUTES);
	if (!IN6_ARE_ADDR_EQUAL (&priv->gateway, &old_gateway))
		_NOTIFY (config, PROP_GATEWAY);

	return config;
}

gboolean
nm_ip6_config_commit (const NMIP6Config *config, int ifindex, gboolean routes_full_sync)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	int i;
	gboolean success;

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	/* Addresses */
	nm_platform_ip6_address_sync (NM_PLATFORM_GET, ifindex, priv->addresses, TRUE);

	/* Routes */
	{
		int count = nm_ip6_config_get_num_routes (config);
		GArray *routes = g_array_sized_new (FALSE, FALSE, sizeof (NMPlatformIP6Route), count);
		const NMPlatformIP6Route *route;

		for (i = 0; i < count; i++) {
			route = nm_ip6_config_get_route (config, i);

			/* Don't add the route if it's more specific than one of the subnets
			 * the device already has an IP address on.
			 */
			if (   IN6_IS_ADDR_UNSPECIFIED (&route->gateway)
			    && nm_ip6_config_destination_is_direct (config, &route->network, route->plen))
				continue;

			g_array_append_vals (routes, route, 1);
		}

		success = nm_route_manager_ip6_route_sync (nm_route_manager_get (), ifindex, routes, TRUE, routes_full_sync);
		g_array_unref (routes);
	}

	return success;
}

void
nm_ip6_config_merge_setting (NMIP6Config *config, NMSettingIPConfig *setting, guint32 default_route_metric)
{
	NMIP6ConfigPrivate *priv;
	guint naddresses, nroutes, nnameservers, nsearches;
	const char *gateway_str;
	int i;

	if (!setting)
		return;

	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	naddresses = nm_setting_ip_config_get_num_addresses (setting);
	nroutes = nm_setting_ip_config_get_num_routes (setting);
	nnameservers = nm_setting_ip_config_get_num_dns (setting);
	nsearches = nm_setting_ip_config_get_num_dns_searches (setting);

	g_object_freeze_notify (G_OBJECT (config));

	/* Gateway */
	if (nm_setting_ip_config_get_never_default (setting))
		nm_ip6_config_set_never_default (config, TRUE);
	else if (nm_setting_ip_config_get_ignore_auto_routes (setting))
		nm_ip6_config_set_never_default (config, FALSE);
	gateway_str = nm_setting_ip_config_get_gateway (setting);
	if (gateway_str) {
		struct in6_addr gateway;

		inet_pton (AF_INET6, gateway_str, &gateway);
		nm_ip6_config_set_gateway (config, &gateway);
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
		address.lifetime = NM_PLATFORM_LIFETIME_PERMANENT;
		address.preferred = NM_PLATFORM_LIFETIME_PERMANENT;
		address.source = NM_IP_CONFIG_SOURCE_USER;

		nm_ip6_config_add_address (config, &address);
	}

	/* Routes */
	if (nm_setting_ip_config_get_ignore_auto_routes (setting))
		nm_ip6_config_reset_routes (config);
	for (i = 0; i < nroutes; i++) {
		NMIPRoute *s_route = nm_setting_ip_config_get_route (setting, i);
		NMPlatformIP6Route route;

		memset (&route, 0, sizeof (route));
		nm_ip_route_get_dest_binary (s_route, &route.network);
		route.plen = nm_ip_route_get_prefix (s_route);
		nm_ip_route_get_next_hop_binary (s_route, &route.gateway);
		if (nm_ip_route_get_metric (s_route) == -1)
			route.metric = default_route_metric;
		else
			route.metric = nm_ip_route_get_metric (s_route);
		route.source = NM_IP_CONFIG_SOURCE_USER;

		g_assert (route.plen > 0);

		nm_ip6_config_add_route (config, &route);
	}

	/* DNS */
	if (nm_setting_ip_config_get_ignore_auto_dns (setting)) {
		nm_ip6_config_reset_nameservers (config);
		nm_ip6_config_reset_domains (config);
		nm_ip6_config_reset_searches (config);
	}
	for (i = 0; i < nnameservers; i++) {
		 struct in6_addr ip;

		if (inet_pton (AF_INET6, nm_setting_ip_config_get_dns (setting, i), &ip) == 1)
			nm_ip6_config_add_nameserver (config, &ip);
	}
	for (i = 0; i < nsearches; i++)
		nm_ip6_config_add_search (config, nm_setting_ip_config_get_dns_search (setting, i));

	i = 0;
	while ((i = nm_setting_ip_config_next_valid_dns_option (setting, i)) >= 0) {
		nm_ip6_config_add_dns_option (config, nm_setting_ip_config_get_dns_option (setting, i));
		i++;
	}

	g_object_thaw_notify (G_OBJECT (config));
}

NMSetting *
nm_ip6_config_create_setting (const NMIP6Config *config)
{
	NMSettingIPConfig *s_ip6;
	const struct in6_addr *gateway;
	guint naddresses, nroutes, nnameservers, nsearches, noptions;
	const char *method = NULL;
	int i;
	gint64 route_metric;

	s_ip6 = NM_SETTING_IP_CONFIG (nm_setting_ip6_config_new ());

	if (!config) {
		g_object_set (s_ip6,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
		              NULL);
		return NM_SETTING (s_ip6);
	}

	gateway = nm_ip6_config_get_gateway (config);
	naddresses = nm_ip6_config_get_num_addresses (config);
	nroutes = nm_ip6_config_get_num_routes (config);
	nnameservers = nm_ip6_config_get_num_nameservers (config);
	nsearches = nm_ip6_config_get_num_searches (config);
	noptions = nm_ip6_config_get_num_dns_options (config);
	route_metric = nm_ip6_config_get_route_metric (config);

	/* Addresses */
	for (i = 0; i < naddresses; i++) {
		const NMPlatformIP6Address *address = nm_ip6_config_get_address (config, i);
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
	for (i = 0; i < nroutes; i++) {
		const NMPlatformIP6Route *route = nm_ip6_config_get_route (config, i);
		NMIPRoute *s_route;

		/* Ignore link-local route. */
		if (IN6_IS_ADDR_LINKLOCAL (&route->network))
			continue;

		/* Ignore default route. */
		if (!route->plen)
			continue;

		/* Ignore routes provided by external sources */
		if (route->source != NM_IP_CONFIG_SOURCE_USER)
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
		const struct in6_addr *nameserver = nm_ip6_config_get_nameserver (config, i);

		nm_setting_ip_config_add_dns (s_ip6, nm_utils_inet6_ntop (nameserver, NULL));
	}
	for (i = 0; i < nsearches; i++) {
		const char *search = nm_ip6_config_get_search (config, i);

		nm_setting_ip_config_add_dns_search (s_ip6, search);
	}
	for (i = 0; i < noptions; i++) {
		const char *option = nm_ip6_config_get_dns_option (config, i);

		nm_setting_ip_config_add_dns_option (s_ip6, option);
	}


	return NM_SETTING (s_ip6);
}

/******************************************************************/

void
nm_ip6_config_merge (NMIP6Config *dst, const NMIP6Config *src)
{
	NMIP6ConfigPrivate *dst_priv, *src_priv;
	guint32 i;

	g_return_if_fail (src != NULL);
	g_return_if_fail (dst != NULL);

	dst_priv = NM_IP6_CONFIG_GET_PRIVATE (dst);
	src_priv = NM_IP6_CONFIG_GET_PRIVATE (src);

	g_object_freeze_notify (G_OBJECT (dst));

	/* addresses */
	for (i = 0; i < nm_ip6_config_get_num_addresses (src); i++)
		nm_ip6_config_add_address (dst, nm_ip6_config_get_address (src, i));

	/* nameservers */
	for (i = 0; i < nm_ip6_config_get_num_nameservers (src); i++)
		nm_ip6_config_add_nameserver (dst, nm_ip6_config_get_nameserver (src, i));

	/* default gateway */
	if (nm_ip6_config_get_gateway (src))
		nm_ip6_config_set_gateway (dst, nm_ip6_config_get_gateway (src));

	/* routes */
	for (i = 0; i < nm_ip6_config_get_num_routes (src); i++)
		nm_ip6_config_add_route (dst, nm_ip6_config_get_route (src, i));

	if (dst_priv->route_metric == -1)
		dst_priv->route_metric = src_priv->route_metric;
	else if (src_priv->route_metric != -1)
		dst_priv->route_metric = MIN (dst_priv->route_metric, src_priv->route_metric);

	/* domains */
	for (i = 0; i < nm_ip6_config_get_num_domains (src); i++)
		nm_ip6_config_add_domain (dst, nm_ip6_config_get_domain (src, i));

	/* dns searches */
	for (i = 0; i < nm_ip6_config_get_num_searches (src); i++)
		nm_ip6_config_add_search (dst, nm_ip6_config_get_search (src, i));

	/* dns options */
	for (i = 0; i < nm_ip6_config_get_num_dns_options (src); i++)
		nm_ip6_config_add_dns_option (dst, nm_ip6_config_get_dns_option (src, i));

	if (nm_ip6_config_get_mss (src))
		nm_ip6_config_set_mss (dst, nm_ip6_config_get_mss (src));

	g_object_thaw_notify (G_OBJECT (dst));
}

gboolean
nm_ip6_config_destination_is_direct (const NMIP6Config *config, const struct in6_addr *network, int plen)
{
	int num = nm_ip6_config_get_num_addresses (config);
	int i;

	for (i = 0; i < num; i++) {
		const NMPlatformIP6Address *item = nm_ip6_config_get_address (config, i);

		if (item->plen <= plen && same_prefix (&item->address, network, item->plen) &&
		    !(item->flags & IFA_F_NOPREFIXROUTE))
			return TRUE;
	}

	return FALSE;
}

/*******************************************************************************/

static int
_addresses_get_index (const NMIP6Config *self, const NMPlatformIP6Address *addr)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->addresses->len; i++) {
		const NMPlatformIP6Address *a = &g_array_index (priv->addresses, NMPlatformIP6Address, i);

		if (IN6_ARE_ADDR_EQUAL (&addr->address, &a->address))
			return (int) i;
	}
	return -1;
}

static int
_nameservers_get_index (const NMIP6Config *self, const struct in6_addr *ns)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->nameservers->len; i++) {
		const struct in6_addr *n = &g_array_index (priv->nameservers, struct in6_addr, i);

		if (IN6_ARE_ADDR_EQUAL (ns, n))
			return (int) i;
	}
	return -1;
}

static int
_routes_get_index (const NMIP6Config *self, const NMPlatformIP6Route *route)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->routes->len; i++) {
		const NMPlatformIP6Route *r = &g_array_index (priv->routes, NMPlatformIP6Route, i);

		if (routes_are_duplicate (route, r, FALSE))
			return (int) i;
	}
	return -1;
}

static int
_domains_get_index (const NMIP6Config *self, const char *domain)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
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
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
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
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->dns_options->len; i++) {
		const char *s = g_ptr_array_index (priv->dns_options, i);

		if (g_strcmp0 (option, s) == 0)
			return (int) i;
	}
	return -1;
}

/*******************************************************************************/

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
	guint i;
	gint idx;
	const struct in6_addr *dst_tmp, *src_tmp;

	g_return_if_fail (src != NULL);
	g_return_if_fail (dst != NULL);

	g_object_freeze_notify (G_OBJECT (dst));

	/* addresses */
	for (i = 0; i < nm_ip6_config_get_num_addresses (src); i++) {
		idx = _addresses_get_index (dst, nm_ip6_config_get_address (src, i));
		if (idx >= 0)
			nm_ip6_config_del_address (dst, idx);
	}

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
	for (i = 0; i < nm_ip6_config_get_num_routes (src); i++) {
		idx = _routes_get_index (dst, nm_ip6_config_get_route (src, i));
		if (idx >= 0)
			nm_ip6_config_del_route (dst, idx);
	}

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

	g_object_thaw_notify (G_OBJECT (dst));
}

void
nm_ip6_config_intersect (NMIP6Config *dst, const NMIP6Config *src)
{
	guint i;
	gint idx;
	const struct in6_addr *dst_tmp, *src_tmp;

	g_return_if_fail (src != NULL);
	g_return_if_fail (dst != NULL);

	g_object_freeze_notify (G_OBJECT (dst));

	/* addresses */
	for (i = 0; i < nm_ip6_config_get_num_addresses (dst); ) {
		idx = _addresses_get_index (src, nm_ip6_config_get_address (dst, i));
		if (idx < 0)
			nm_ip6_config_del_address (dst, i);
		else
			i++;
	}

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
	for (i = 0; i < nm_ip6_config_get_num_routes (dst); ) {
		idx = _routes_get_index (src, nm_ip6_config_get_route (dst, i));
		if (idx < 0)
			nm_ip6_config_del_route (dst, i);
		else
			i++;
	}

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
#ifndef G_DISABLE_ASSERT
	gboolean config_equal;
#endif
	gboolean has_minor_changes = FALSE, has_relevant_changes = FALSE, are_equal;
	guint i, num;
	NMIP6ConfigPrivate *dst_priv, *src_priv;
	const NMPlatformIP6Address *dst_addr, *src_addr;
	const NMPlatformIP6Route *dst_route, *src_route;

	g_return_val_if_fail (src != NULL, FALSE);
	g_return_val_if_fail (dst != NULL, FALSE);
	g_return_val_if_fail (src != dst, FALSE);

#ifndef G_DISABLE_ASSERT
	config_equal = nm_ip6_config_equal (dst, src);
#endif

	dst_priv = NM_IP6_CONFIG_GET_PRIVATE (dst);
	src_priv = NM_IP6_CONFIG_GET_PRIVATE (src);

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
	num = nm_ip6_config_get_num_addresses (src);
	are_equal = num == nm_ip6_config_get_num_addresses (dst);
	if (are_equal) {
		for (i = 0; i < num; i++ ) {
			if (nm_platform_ip6_address_cmp (src_addr = nm_ip6_config_get_address (src, i),
			                                 dst_addr = nm_ip6_config_get_address (dst, i))) {
				are_equal = FALSE;
				if (!addresses_are_duplicate (src_addr, dst_addr, TRUE)) {
					has_relevant_changes = TRUE;
					break;
				}
			}
		}
	} else
		has_relevant_changes = TRUE;
	if (!are_equal) {
		nm_ip6_config_reset_addresses (dst);
		for (i = 0; i < num; i++)
			nm_ip6_config_add_address (dst, nm_ip6_config_get_address (src, i));
		has_minor_changes = TRUE;
	}

	/* routes */
	num = nm_ip6_config_get_num_routes (src);
	are_equal = num == nm_ip6_config_get_num_routes (dst);
	if (are_equal) {
		for (i = 0; i < num; i++ ) {
			if (nm_platform_ip6_route_cmp (src_route = nm_ip6_config_get_route (src, i),
			                               dst_route = nm_ip6_config_get_route (dst, i))) {
				are_equal = FALSE;
				if (!routes_are_duplicate (src_route, dst_route, TRUE)) {
					has_relevant_changes = TRUE;
					break;
				}
			}
		}
	} else
		has_relevant_changes = TRUE;
	if (!are_equal) {
		nm_ip6_config_reset_routes (dst);
		for (i = 0; i < num; i++)
			nm_ip6_config_add_route (dst, nm_ip6_config_get_route (src, i));
		has_minor_changes = TRUE;
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

	/* config_equal does not compare *all* the fields, therefore, we might have has_minor_changes
	 * regardless of config_equal. But config_equal must correspond to has_relevant_changes. */
	g_assert (config_equal == !has_relevant_changes);

	g_object_thaw_notify (G_OBJECT (dst));

	if (relevant_changes)
		*relevant_changes = has_relevant_changes;

	return has_relevant_changes || has_minor_changes;
}

void
nm_ip6_config_dump (const NMIP6Config *config, const char *detail)
{
	const struct in6_addr *tmp;
	guint32 i;
	const char *str;

	g_return_if_fail (config != NULL);

	g_message ("--------- NMIP6Config %p (%s)", config, detail);

	str = nm_ip6_config_get_dbus_path (config);
	if (str)
		g_message ("   path: %s", str);

	/* addresses */
	for (i = 0; i < nm_ip6_config_get_num_addresses (config); i++)
		g_message ("      a: %s", nm_platform_ip6_address_to_string (nm_ip6_config_get_address (config, i)));

	/* default gateway */
	tmp = nm_ip6_config_get_gateway (config);
	if (tmp)
		g_message ("     gw: %s", nm_utils_inet6_ntop (tmp, NULL));

	/* nameservers */
	for (i = 0; i < nm_ip6_config_get_num_nameservers (config); i++) {
		tmp = nm_ip6_config_get_nameserver (config, i);
		g_message ("     ns: %s", nm_utils_inet6_ntop (tmp, NULL));
	}

	/* routes */
	for (i = 0; i < nm_ip6_config_get_num_routes (config); i++)
		g_message ("     rt: %s", nm_platform_ip6_route_to_string (nm_ip6_config_get_route (config, i)));

	/* domains */
	for (i = 0; i < nm_ip6_config_get_num_domains (config); i++)
		g_message (" domain: %s", nm_ip6_config_get_domain (config, i));

	/* dns searches */
	for (i = 0; i < nm_ip6_config_get_num_searches (config); i++)
		g_message (" search: %s", nm_ip6_config_get_search (config, i));

	/* dns options */
	for (i = 0; i < nm_ip6_config_get_num_dns_options (config); i++)
		g_message (" dnsopt: %s", nm_ip6_config_get_dns_option (config, i));

	g_message ("    mss: %"G_GUINT32_FORMAT, nm_ip6_config_get_mss (config));
	g_message (" n-dflt: %d", nm_ip6_config_get_never_default (config));
}

/******************************************************************/

void
nm_ip6_config_set_never_default (NMIP6Config *config, gboolean never_default)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	priv->never_default = !!never_default;
}

gboolean
nm_ip6_config_get_never_default (const NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return priv->never_default;
}

void
nm_ip6_config_set_gateway (NMIP6Config *config, const struct in6_addr *gateway)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	if (gateway) {
		if (IN6_ARE_ADDR_EQUAL (&priv->gateway, gateway))
			return;
		priv->gateway = *gateway;
	} else {
		if (IN6_IS_ADDR_UNSPECIFIED (&priv->gateway))
			return;
		memset (&priv->gateway, 0, sizeof (priv->gateway));
	}
	_NOTIFY (config, PROP_GATEWAY);
}

const struct in6_addr *
nm_ip6_config_get_gateway (const NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return IN6_IS_ADDR_UNSPECIFIED (&priv->gateway) ? NULL : &priv->gateway;
}

gint64
nm_ip6_config_get_route_metric (const NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return priv->route_metric;
}

/******************************************************************/

void
nm_ip6_config_reset_addresses (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	if (priv->addresses->len != 0) {
		g_array_set_size (priv->addresses, 0);
		_NOTIFY (config, PROP_ADDRESS_DATA);
		_NOTIFY (config, PROP_ADDRESSES);
	}
}

/**
 * nm_ip6_config_add_address:
 * @config: the #NMIP6Config
 * @new: the new address to add to @config
 *
 * Adds the new address to @config.  If an address with the same basic properties
 * (address, prefix) already exists in @config, it is overwritten with the
 * lifetime and preferred of @new.  The source is also overwritten by the source
 * from @new if that source is higher priority.
 */
void
nm_ip6_config_add_address (NMIP6Config *config, const NMPlatformIP6Address *new)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	NMPlatformIP6Address item_old;
	int i;

	g_return_if_fail (new != NULL);

	for (i = 0; i < priv->addresses->len; i++ ) {
		NMPlatformIP6Address *item = &g_array_index (priv->addresses, NMPlatformIP6Address, i);

		if (IN6_ARE_ADDR_EQUAL (&item->address, &new->address)) {
			if (nm_platform_ip6_address_cmp (item, new) == 0)
				return;

			/* remember the old values. */
			item_old = *item;
			/* Copy over old item to get new lifetime, timestamp, preferred */
			*item = *new;

			/* But restore highest priority source */
			item->source = MAX (item_old.source, new->source);

			/* for addresses that we read from the kernel, we keep the timestamps as defined
			 * by the previous source (item_old). The reason is, that the other source configured the lifetimes
			 * with "what should be" and the kernel values are "what turned out after configuring it".
			 *
			 * For other sources, the longer lifetime wins. */
			if (   (new->source == NM_IP_CONFIG_SOURCE_KERNEL && new->source != item_old.source)
			    || nm_platform_ip_address_cmp_expiry ((const NMPlatformIPAddress *) &item_old, (const NMPlatformIPAddress *) new) > 0) {
				item->timestamp = item_old.timestamp;
				item->lifetime = item_old.lifetime;
				item->preferred = item_old.preferred;
			}
			if (nm_platform_ip6_address_cmp (&item_old, item) == 0)
				return;
			goto NOTIFY;
		}
	}

	g_array_append_val (priv->addresses, *new);
NOTIFY:
	_NOTIFY (config, PROP_ADDRESS_DATA);
	_NOTIFY (config, PROP_ADDRESSES);
}

void
nm_ip6_config_del_address (NMIP6Config *config, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->addresses->len);

	g_array_remove_index (priv->addresses, i);
	_NOTIFY (config, PROP_ADDRESS_DATA);
	_NOTIFY (config, PROP_ADDRESSES);
}

guint
nm_ip6_config_get_num_addresses (const NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return priv->addresses->len;
}

const NMPlatformIP6Address *
nm_ip6_config_get_address (const NMIP6Config *config, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return &g_array_index (priv->addresses, NMPlatformIP6Address, i);
}

gboolean
nm_ip6_config_address_exists (const NMIP6Config *config,
                              const NMPlatformIP6Address *needle)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	guint i;

	for (i = 0; i < priv->addresses->len; i++) {
		const NMPlatformIP6Address *haystack = &g_array_index (priv->addresses, NMPlatformIP6Address, i);

		if (   IN6_ARE_ADDR_EQUAL (&needle->address, &haystack->address)
		    && needle->plen == haystack->plen)
			return TRUE;
	}
	return FALSE;
}

/******************************************************************/

void
nm_ip6_config_reset_routes (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	if (priv->routes->len != 0) {
		g_array_set_size (priv->routes, 0);
		_NOTIFY (config, PROP_ROUTE_DATA);
		_NOTIFY (config, PROP_ROUTES);
	}
}

/**
 * nm_ip6_config_add_route:
 * @config: the #NMIP6Config
 * @new: the new route to add to @config
 *
 * Adds the new route to @config.  If a route with the same basic properties
 * (network, prefix) already exists in @config, it is overwritten including the
 * gateway and metric of @new.  The source is also overwritten by the source
 * from @new if that source is higher priority.
 */
void
nm_ip6_config_add_route (NMIP6Config *config, const NMPlatformIP6Route *new)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	NMIPConfigSource old_source;
	int i;

	g_return_if_fail (new != NULL);
	g_return_if_fail (new->plen > 0);
	g_assert (priv->ifindex);

	for (i = 0; i < priv->routes->len; i++ ) {
		NMPlatformIP6Route *item = &g_array_index (priv->routes, NMPlatformIP6Route, i);

		if (routes_are_duplicate (item, new, FALSE)) {
			if (nm_platform_ip6_route_cmp (item, new) == 0)
				return;
			old_source = item->source;
			*item = *new;
			/* Restore highest priority source */
			item->source = MAX (old_source, new->source);
			item->ifindex = priv->ifindex;
			goto NOTIFY;
		}
	}

	g_array_append_val (priv->routes, *new);
	g_array_index (priv->routes, NMPlatformIP6Route, priv->routes->len - 1).ifindex = priv->ifindex;
NOTIFY:
	_NOTIFY (config, PROP_ROUTE_DATA);
	_NOTIFY (config, PROP_ROUTES);
}

void
nm_ip6_config_del_route (NMIP6Config *config, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->routes->len);

	g_array_remove_index (priv->routes, i);
	_NOTIFY (config, PROP_ROUTE_DATA);
	_NOTIFY (config, PROP_ROUTES);
}

guint
nm_ip6_config_get_num_routes (const NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return priv->routes->len;
}

const NMPlatformIP6Route *
nm_ip6_config_get_route (const NMIP6Config *config, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return &g_array_index (priv->routes, NMPlatformIP6Route, i);
}

const NMPlatformIP6Route *
nm_ip6_config_get_direct_route_for_host (const NMIP6Config *config, const struct in6_addr *host)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	guint i;
	struct in6_addr network2, host2;
	NMPlatformIP6Route *best_route = NULL;

	g_return_val_if_fail (host && !IN6_IS_ADDR_UNSPECIFIED (host), NULL);

	for (i = 0; i < priv->routes->len; i++) {
		NMPlatformIP6Route *item = &g_array_index (priv->routes, NMPlatformIP6Route, i);

		if (!IN6_IS_ADDR_UNSPECIFIED (&item->gateway))
			continue;

		if (best_route && best_route->plen > item->plen)
			continue;

		nm_utils_ip6_address_clear_host_address (&host2, host, item->plen);
		nm_utils_ip6_address_clear_host_address (&network2, &item->network, item->plen);

		if (!IN6_ARE_ADDR_EQUAL (&network2, &host2))
			continue;

		if (best_route &&
		    nm_utils_ip6_route_metric_normalize (best_route->metric) <= nm_utils_ip6_route_metric_normalize (item->metric))
			continue;

		best_route = item;
	}

	return best_route;
}

const NMPlatformIP6Address *
nm_ip6_config_get_subnet_for_host (const NMIP6Config *config, const struct in6_addr *host)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	guint i;
	NMPlatformIP6Address *subnet = NULL;
	struct in6_addr subnet2, host2;

	g_return_val_if_fail (host && !IN6_IS_ADDR_UNSPECIFIED (host), NULL);

	for (i = 0; i < priv->addresses->len; i++) {
		NMPlatformIP6Address *item = &g_array_index (priv->addresses, NMPlatformIP6Address, i);

		if (subnet && subnet->plen >= item->plen)
			continue;

		nm_utils_ip6_address_clear_host_address (&host2, host, item->plen);
		nm_utils_ip6_address_clear_host_address (&subnet2, &item->address, item->plen);

		if (IN6_ARE_ADDR_EQUAL (&subnet2, &host2))
			subnet = item;
	}

	return subnet;
}


/******************************************************************/

void
nm_ip6_config_reset_nameservers (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	if (priv->nameservers->len != 0) {
		g_array_set_size (priv->nameservers, 0);
		_NOTIFY (config, PROP_NAMESERVERS);
	}
}

void
nm_ip6_config_add_nameserver (NMIP6Config *config, const struct in6_addr *new)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	int i;

	g_return_if_fail (new != NULL);

	for (i = 0; i < priv->nameservers->len; i++)
		if (IN6_ARE_ADDR_EQUAL (new, &g_array_index (priv->nameservers, struct in6_addr, i)))
			return;

	g_array_append_val (priv->nameservers, *new);
	_NOTIFY (config, PROP_NAMESERVERS);
}

void
nm_ip6_config_del_nameserver (NMIP6Config *config, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->nameservers->len);

	g_array_remove_index (priv->nameservers, i);
	_NOTIFY (config, PROP_NAMESERVERS);
}

guint32
nm_ip6_config_get_num_nameservers (const NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return priv->nameservers->len;
}

const struct in6_addr *
nm_ip6_config_get_nameserver (const NMIP6Config *config, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return &g_array_index (priv->nameservers, struct in6_addr, i);
}

/******************************************************************/

void
nm_ip6_config_reset_domains (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	if (priv->domains->len != 0) {
		g_ptr_array_set_size (priv->domains, 0);
		_NOTIFY (config, PROP_DOMAINS);
	}
}

void
nm_ip6_config_add_domain (NMIP6Config *config, const char *domain)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	int i;

	g_return_if_fail (domain != NULL);
	g_return_if_fail (domain[0] != '\0');

	for (i = 0; i < priv->domains->len; i++)
		if (!g_strcmp0 (g_ptr_array_index (priv->domains, i), domain))
			return;

	g_ptr_array_add (priv->domains, g_strdup (domain));
	_NOTIFY (config, PROP_DOMAINS);
}

void
nm_ip6_config_del_domain (NMIP6Config *config, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->domains->len);

	g_ptr_array_remove_index (priv->domains, i);
	_NOTIFY (config, PROP_DOMAINS);
}

guint32
nm_ip6_config_get_num_domains (const NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return priv->domains->len;
}

const char *
nm_ip6_config_get_domain (const NMIP6Config *config, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return g_ptr_array_index (priv->domains, i);
}

/******************************************************************/

void
nm_ip6_config_reset_searches (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	if (priv->searches->len != 0) {
		g_ptr_array_set_size (priv->searches, 0);
		_NOTIFY (config, PROP_SEARCHES);
	}
}

void
nm_ip6_config_add_search (NMIP6Config *config, const char *new)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	int i;

	g_return_if_fail (new != NULL);
	g_return_if_fail (new[0] != '\0');

	for (i = 0; i < priv->searches->len; i++)
		if (!g_strcmp0 (g_ptr_array_index (priv->searches, i), new))
			return;

	g_ptr_array_add (priv->searches, g_strdup (new));
	_NOTIFY (config, PROP_SEARCHES);
}

void
nm_ip6_config_del_search (NMIP6Config *config, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->searches->len);

	g_ptr_array_remove_index (priv->searches, i);
	_NOTIFY (config, PROP_SEARCHES);
}

guint32
nm_ip6_config_get_num_searches (const NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return priv->searches->len;
}

const char *
nm_ip6_config_get_search (const NMIP6Config *config, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return g_ptr_array_index (priv->searches, i);
}

/******************************************************************/

void
nm_ip6_config_reset_dns_options (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	if (priv->dns_options->len != 0) {
		g_ptr_array_set_size (priv->dns_options, 0);
		_NOTIFY (config, PROP_DNS_OPTIONS);
	}
}

void
nm_ip6_config_add_dns_option (NMIP6Config *config, const char *new)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	int i;

	g_return_if_fail (new != NULL);
	g_return_if_fail (new[0] != '\0');

	for (i = 0; i < priv->dns_options->len; i++)
		if (!g_strcmp0 (g_ptr_array_index (priv->dns_options, i), new))
			return;

	g_ptr_array_add (priv->dns_options, g_strdup (new));
	_NOTIFY (config, PROP_DNS_OPTIONS);
}

void
nm_ip6_config_del_dns_option (NMIP6Config *config, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->dns_options->len);

	g_ptr_array_remove_index (priv->dns_options, i);
	_NOTIFY (config, PROP_DNS_OPTIONS);
}

guint32
nm_ip6_config_get_num_dns_options (const NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return priv->dns_options->len;
}

const char *
nm_ip6_config_get_dns_option (const NMIP6Config *config, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return g_ptr_array_index (priv->dns_options, i);
}

/******************************************************************/

void
nm_ip6_config_set_mss (NMIP6Config *config, guint32 mss)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	priv->mss = mss;
}

guint32
nm_ip6_config_get_mss (const NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return priv->mss;
}

/******************************************************************/

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
nm_ip6_config_hash (const NMIP6Config *config, GChecksum *sum, gboolean dns_only)
{
	guint32 i;
	const char *s;

	g_return_if_fail (config);
	g_return_if_fail (sum);

	if (dns_only == FALSE) {
		hash_in6addr (sum, nm_ip6_config_get_gateway (config));

		for (i = 0; i < nm_ip6_config_get_num_addresses (config); i++) {
			const NMPlatformIP6Address *address = nm_ip6_config_get_address (config, i);

			hash_in6addr (sum, &address->address);
			hash_u32 (sum, address->plen);
		}

		for (i = 0; i < nm_ip6_config_get_num_routes (config); i++) {
			const NMPlatformIP6Route *route = nm_ip6_config_get_route (config, i);

			hash_in6addr (sum, &route->network);
			hash_u32 (sum, route->plen);
			hash_in6addr (sum, &route->gateway);
			hash_u32 (sum, route->metric);
		}
	}

	for (i = 0; i < nm_ip6_config_get_num_nameservers (config); i++)
		hash_in6addr (sum, nm_ip6_config_get_nameserver (config, i));

	for (i = 0; i < nm_ip6_config_get_num_domains (config); i++) {
		s = nm_ip6_config_get_domain (config, i);
		g_checksum_update (sum, (const guint8 *) s, strlen (s));
	}

	for (i = 0; i < nm_ip6_config_get_num_searches (config); i++) {
		s = nm_ip6_config_get_search (config, i);
		g_checksum_update (sum, (const guint8 *) s, strlen (s));
	}

	for (i = 0; i < nm_ip6_config_get_num_dns_options (config); i++) {
		s = nm_ip6_config_get_dns_option (config, i);
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

/******************************************************************/

static void
nm_ip6_config_init (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	priv->addresses = g_array_new (FALSE, TRUE, sizeof (NMPlatformIP6Address));
	priv->routes = g_array_new (FALSE, TRUE, sizeof (NMPlatformIP6Route));
	priv->nameservers = g_array_new (FALSE, TRUE, sizeof (struct in6_addr));
	priv->domains = g_ptr_array_new_with_free_func (g_free);
	priv->searches = g_ptr_array_new_with_free_func (g_free);
	priv->dns_options = g_ptr_array_new_with_free_func (g_free);
	priv->route_metric = -1;
}

static void
finalize (GObject *object)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (object);

	g_free (priv->path);

	g_array_unref (priv->addresses);
	g_array_unref (priv->routes);
	g_array_unref (priv->nameservers);
	g_ptr_array_unref (priv->domains);
	g_ptr_array_unref (priv->searches);
	g_ptr_array_unref (priv->dns_options);

	G_OBJECT_CLASS (nm_ip6_config_parent_class)->finalize (object);
}

static void
nameservers_to_gvalue (GArray *array, GValue *value)
{
	GPtrArray *dns;
	guint i = 0;

	dns = g_ptr_array_new ();

	while (array && (i < array->len)) {
		struct in6_addr *addr;
		GByteArray *bytearray;
		addr = &g_array_index (array, struct in6_addr, i++);

		bytearray = g_byte_array_sized_new (16);
		g_byte_array_append (bytearray, (guint8 *) addr->s6_addr, 16);
		g_ptr_array_add (dns, bytearray);
	}

	g_value_take_boxed (value, dns);
}

static void
gvalue_destroy (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMIP6Config *config = NM_IP6_CONFIG (object);
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_IFINDEX:
		g_value_set_int (value, priv->ifindex);
		break;
	case PROP_ADDRESS_DATA:
		{
			GPtrArray *addresses = g_ptr_array_new ();
			int naddr = nm_ip6_config_get_num_addresses (config);
			int i;

			for (i = 0; i < naddr; i++) {
				const NMPlatformIP6Address *address = nm_ip6_config_get_address (config, i);
				GHashTable *addr_hash;
				GValue *val;

				addr_hash = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, gvalue_destroy);

				val = g_slice_new0 (GValue);
				g_value_init (val, G_TYPE_STRING);
				g_value_set_string (val, nm_utils_inet6_ntop (&address->address, NULL));
				g_hash_table_insert (addr_hash, "address", val);

				val = g_slice_new0 (GValue);
				g_value_init (val, G_TYPE_UINT);
				g_value_set_uint (val, address->plen);
				g_hash_table_insert (addr_hash, "prefix", val);

				g_ptr_array_add (addresses, addr_hash);
			}

			g_value_take_boxed (value, addresses);
		}
		break;
	case PROP_ADDRESSES:
		{
			GPtrArray *addresses = g_ptr_array_new ();
			const struct in6_addr *gateway = nm_ip6_config_get_gateway (config);
			int naddr = nm_ip6_config_get_num_addresses (config);
			int i;

			for (i = 0; i < naddr; i++) {
				const NMPlatformIP6Address *address = nm_ip6_config_get_address (config, i);

				GValueArray *array = g_value_array_new (3);
				GValue element = G_VALUE_INIT;
				GByteArray *ba;

				/* IP address */
				g_value_init (&element, DBUS_TYPE_G_UCHAR_ARRAY);
				ba = g_byte_array_new ();
				g_byte_array_append (ba, (guint8 *) &address->address, 16);
				g_value_take_boxed (&element, ba);
				g_value_array_append (array, &element);
				g_value_unset (&element);

				/* Prefix */
				g_value_init (&element, G_TYPE_UINT);
				g_value_set_uint (&element, address->plen);
				g_value_array_append (array, &element);
				g_value_unset (&element);

				/* Gateway */
				g_value_init (&element, DBUS_TYPE_G_UCHAR_ARRAY);
				ba = g_byte_array_new ();
				g_byte_array_append (ba, (guint8 *) (i == 0 && gateway ? gateway : &in6addr_any), sizeof (*gateway));
				g_value_take_boxed (&element, ba);
				g_value_array_append (array, &element);
				g_value_unset (&element);

				g_ptr_array_add (addresses, array);
			}

			g_value_take_boxed (value, addresses);
		}
		break;
	case PROP_ROUTE_DATA:
		{
			GPtrArray *routes = g_ptr_array_new ();
			guint nroutes = nm_ip6_config_get_num_routes (config);
			int i;

			for (i = 0; i < nroutes; i++) {
				const NMPlatformIP6Route *route = nm_ip6_config_get_route (config, i);
				GHashTable *route_hash;
				GValue *val;

				route_hash = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, gvalue_destroy);

				val = g_slice_new0 (GValue);
				g_value_init (val, G_TYPE_STRING);
				g_value_set_string (val, nm_utils_inet6_ntop (&route->network, NULL));
				g_hash_table_insert (route_hash, "dest", val);

				val = g_slice_new0 (GValue);
				g_value_init (val, G_TYPE_UINT);
				g_value_set_uint (val, route->plen);
				g_hash_table_insert (route_hash, "prefix", val);

				if (!IN6_IS_ADDR_UNSPECIFIED (&route->gateway)) {
					val = g_slice_new0 (GValue);
					g_value_init (val, G_TYPE_STRING);
					g_value_set_string (val, nm_utils_inet6_ntop (&route->gateway, NULL));
					g_hash_table_insert (route_hash, "next-hop", val);
				}

				val = g_slice_new0 (GValue);
				g_value_init (val, G_TYPE_UINT);
				g_value_set_uint (val, route->metric);
				g_hash_table_insert (route_hash, "metric", val);

				g_ptr_array_add (routes, route_hash);
			}

			g_value_take_boxed (value, routes);
		}
		break;
	case PROP_ROUTES:
		{
			GPtrArray *routes = g_ptr_array_new ();
			int nroutes = nm_ip6_config_get_num_routes (config);
			int i;

			for (i = 0; i < nroutes; i++) {
				GValueArray *array;
				const NMPlatformIP6Route *route = nm_ip6_config_get_route (config, i);
				GByteArray *ba;
				GValue element = G_VALUE_INIT;

				/* legacy versions of nm_ip6_route_set_prefix() in libnm-util assert that the
				 * plen is positive. Skip the default routes not to break older clients. */
				if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT (route))
					continue;

				array = g_value_array_new (4);

				g_value_init (&element, DBUS_TYPE_G_UCHAR_ARRAY);
				ba = g_byte_array_new ();
				g_byte_array_append (ba, (guint8 *) &route->network, sizeof (route->network));
				g_value_take_boxed (&element, ba);
				g_value_array_append (array, &element);
				g_value_unset (&element);

				g_value_init (&element, G_TYPE_UINT);
				g_value_set_uint (&element, route->plen);
				g_value_array_append (array, &element);
				g_value_unset (&element);

				g_value_init (&element, DBUS_TYPE_G_UCHAR_ARRAY);
				ba = g_byte_array_new ();
				g_byte_array_append (ba, (guint8 *) &route->gateway, sizeof (route->gateway));
				g_value_take_boxed (&element, ba);
				g_value_array_append (array, &element);
				g_value_unset (&element);

				g_value_init (&element, G_TYPE_UINT);
				g_value_set_uint (&element, route->metric);
				g_value_array_append (array, &element);
				g_value_unset (&element);

				g_ptr_array_add (routes, array);
			}

			g_value_take_boxed (value, routes);
		}
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
		g_value_set_boxed (value, priv->domains);
		break;
	case PROP_SEARCHES:
		g_value_set_boxed (value, priv->searches);
		break;
	case PROP_DNS_OPTIONS:
		g_value_set_boxed (value, priv->dns_options);
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
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_IFINDEX:
		priv->ifindex = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_ip6_config_class_init (NMIP6ConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMIP6ConfigPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize = finalize;

	/* properties */
	obj_properties[PROP_IFINDEX] =
		 g_param_spec_int (NM_IP6_CONFIG_IFINDEX, "", "",
		                   -1, G_MAXINT, -1,
		                   G_PARAM_READWRITE |
		                   G_PARAM_CONSTRUCT_ONLY |
		                   G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ADDRESS_DATA] =
	    g_param_spec_boxed (NM_IP6_CONFIG_ADDRESS_DATA, "", "",
	                        DBUS_TYPE_NM_IP_ADDRESSES,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ADDRESSES] =
		g_param_spec_boxed (NM_IP6_CONFIG_ADDRESSES, "", "",
		                    DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ROUTE_DATA] =
		g_param_spec_boxed (NM_IP6_CONFIG_ROUTE_DATA, "", "",
		                    DBUS_TYPE_NM_IP_ROUTES,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ROUTES] =
	    g_param_spec_boxed (NM_IP6_CONFIG_ROUTES, "", "",
	                        DBUS_TYPE_G_ARRAY_OF_IP6_ROUTE,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_GATEWAY] =
		g_param_spec_string (NM_IP6_CONFIG_GATEWAY, "", "",
		                     NULL,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_NAMESERVERS] =
	    g_param_spec_boxed (NM_IP6_CONFIG_NAMESERVERS, "", "",
	                        DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UCHAR,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DOMAINS] =
	    g_param_spec_boxed (NM_IP6_CONFIG_DOMAINS, "", "",
	                        DBUS_TYPE_G_ARRAY_OF_STRING,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_SEARCHES] =
	    g_param_spec_boxed (NM_IP6_CONFIG_SEARCHES, "", "",
	                        DBUS_TYPE_G_ARRAY_OF_STRING,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DNS_OPTIONS] =
	    g_param_spec_boxed (NM_IP6_CONFIG_DNS_OPTIONS, "", "",
	                        DBUS_TYPE_G_ARRAY_OF_STRING,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, LAST_PROP, obj_properties);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (config_class),
	                                        &dbus_glib_nm_ip6_config_object_info);
}
