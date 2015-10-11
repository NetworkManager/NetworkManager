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
 * Copyright (C) 2005 - 2014 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "config.h"

#include <string.h>
#include <arpa/inet.h>

#include "nm-ip4-config.h"

#include "nm-default.h"
#include "nm-utils.h"
#include "nm-platform.h"
#include "NetworkManagerUtils.h"
#include "nm-core-internal.h"
#include "nm-route-manager.h"
#include "nm-core-internal.h"
#include "nm-macros-internal.h"

#include "nmdbus-ip4-config.h"

G_DEFINE_TYPE (NMIP4Config, nm_ip4_config, NM_TYPE_EXPORTED_OBJECT)

#define NM_IP4_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IP4_CONFIG, NMIP4ConfigPrivate))

typedef struct {
	gboolean never_default;
	guint32 gateway;
	gboolean has_gateway;
	GArray *addresses;
	GArray *routes;
	GArray *nameservers;
	GPtrArray *domains;
	GPtrArray *searches;
	GPtrArray *dns_options;
	guint32 mss;
	GArray *nis;
	char *nis_domain;
	GArray *wins;
	guint32 mtu;
	NMIPConfigSource mtu_source;
	int ifindex;
	gint64 route_metric;
	gboolean metered;
} NMIP4ConfigPrivate;

/* internal guint32 are assigned to gobject properties of type uint. Ensure, that uint is large enough */
G_STATIC_ASSERT (sizeof (uint) >= sizeof (guint32));
G_STATIC_ASSERT (G_MAXUINT >= 0xFFFFFFFF);

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
	PROP_WINS_SERVERS,

	LAST_PROP
};
static GParamSpec *obj_properties[LAST_PROP] = { NULL, };
#define _NOTIFY(config, prop)    G_STMT_START { g_object_notify_by_pspec (G_OBJECT (config), obj_properties[prop]); } G_STMT_END

NMIP4Config *
nm_ip4_config_new (int ifindex)
{
	g_return_val_if_fail (ifindex >= -1, NULL);
	return (NMIP4Config *) g_object_new (NM_TYPE_IP4_CONFIG,
	                                     NM_IP4_CONFIG_IFINDEX, ifindex,
	                                     NULL);
}

int
nm_ip4_config_get_ifindex (const NMIP4Config *config)
{
	return NM_IP4_CONFIG_GET_PRIVATE (config)->ifindex;
}

static gboolean
same_prefix (guint32 address1, guint32 address2, int plen)
{
	guint32 masked1 = ntohl (address1) >> (32 - plen);
	guint32 masked2 = ntohl (address2) >> (32 - plen);

	return masked1 == masked2;
}

/******************************************************************/

/**
 * nm_ip4_config_capture_resolv_conf():
 * @nameservers: array of guint32
 * @rc_contents: the contents of a resolv.conf or %NULL to read /etc/resolv.conf
 *
 * Reads all resolv.conf IPv4 nameservers and adds them to @nameservers.
 *
 * Returns: %TRUE if nameservers were added, %FALSE if @nameservers is unchanged
 */
gboolean
nm_ip4_config_capture_resolv_conf (GArray *nameservers,
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
		guint32 ns = 0;

		if (!inet_pton (AF_INET, s, (void *) &ns) || !ns)
			continue;

		/* Ignore duplicates */
		for (j = 0; j < nameservers->len; j++) {
			if (g_array_index (nameservers, guint32, j) == ns)
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

			if (_nm_utils_dns_option_validate (s, NULL, NULL, FALSE, _nm_utils_dns_option_descs) &&
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
addresses_are_duplicate (const NMPlatformIP4Address *a, const NMPlatformIP4Address *b)
{
	return    a->address == b->address
	       && a->plen == b->plen
	       && nm_platform_ip4_address_equal_peer_net (a, b);
}

static gboolean
routes_are_duplicate (const NMPlatformIP4Route *a, const NMPlatformIP4Route *b, gboolean consider_gateway_and_metric)
{
	return a->network == b->network && a->plen == b->plen &&
	       (!consider_gateway_and_metric || (a->gateway == b->gateway && a->metric == b->metric));
}

NMIP4Config *
nm_ip4_config_capture (int ifindex, gboolean capture_resolv_conf)
{
	NMIP4Config *config;
	NMIP4ConfigPrivate *priv;
	guint i;
	guint32 lowest_metric = G_MAXUINT32;
	guint32 old_gateway = 0;
	gboolean old_has_gateway = FALSE;

	/* Slaves have no IP configuration */
	if (nm_platform_link_get_master (NM_PLATFORM_GET, ifindex) > 0)
		return NULL;

	config = nm_ip4_config_new (ifindex);
	priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_array_unref (priv->addresses);
	g_array_unref (priv->routes);

	priv->addresses = nm_platform_ip4_address_get_all (NM_PLATFORM_GET, ifindex);
	priv->routes = nm_platform_ip4_route_get_all (NM_PLATFORM_GET, ifindex, NM_PLATFORM_GET_ROUTE_FLAGS_WITH_DEFAULT | NM_PLATFORM_GET_ROUTE_FLAGS_WITH_NON_DEFAULT);

	/* Extract gateway from default route */
	old_gateway = priv->gateway;
	old_has_gateway = priv->has_gateway;
	for (i = 0; i < priv->routes->len; ) {
		const NMPlatformIP4Route *route = &g_array_index (priv->routes, NMPlatformIP4Route, i);

		if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT (route)) {
			if (route->metric < lowest_metric) {
				priv->gateway = route->gateway;
				lowest_metric = route->metric;
			}
			priv->has_gateway = TRUE;
			/* Remove the default route from the list */
			g_array_remove_index_fast (priv->routes, i);
			continue;
		}
		i++;
	}

	/* we detect the route metric based on the default route. All non-default
	 * routes have their route metrics explicitly set. */
	priv->route_metric = priv->has_gateway ? (gint64) lowest_metric : (gint64) -1;

	/* If there is a host route to the gateway, ignore that route.  It is
	 * automatically added by NetworkManager when needed.
	 */
	if (priv->has_gateway) {
		for (i = 0; i < priv->routes->len; i++) {
			const NMPlatformIP4Route *route = &g_array_index (priv->routes, NMPlatformIP4Route, i);

			if (   (route->plen == 32)
			    && (route->network == priv->gateway)
			    && (route->gateway == 0)) {
				g_array_remove_index (priv->routes, i);
				i--;
			}
		}
	}

	/* If the interface has the default route, and has IPv4 addresses, capture
	 * nameservers from /etc/resolv.conf.
	 */
	if (priv->addresses->len && priv->has_gateway && capture_resolv_conf) {
		if (nm_ip4_config_capture_resolv_conf (priv->nameservers, priv->dns_options, NULL))
			_NOTIFY (config, PROP_NAMESERVERS);
	}

	/* actually, nobody should be connected to the signal, just to be sure, notify */
	_NOTIFY (config, PROP_ADDRESS_DATA);
	_NOTIFY (config, PROP_ROUTE_DATA);
	_NOTIFY (config, PROP_ADDRESSES);
	_NOTIFY (config, PROP_ROUTES);
	if (   priv->gateway != old_gateway
	    || priv->has_gateway != old_has_gateway)
		_NOTIFY (config, PROP_GATEWAY);

	return config;
}

gboolean
nm_ip4_config_commit (const NMIP4Config *config, int ifindex, gboolean routes_full_sync, gint64 default_route_metric)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	int i;
	gs_unref_ptrarray GPtrArray *added_addresses = NULL;

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	/* Addresses */
	nm_platform_ip4_address_sync (NM_PLATFORM_GET, ifindex, priv->addresses,
	                              default_route_metric >= 0 ? &added_addresses : NULL);

	/* Routes */
	{
		int count = nm_ip4_config_get_num_routes (config);
		GArray *routes = g_array_sized_new (FALSE, FALSE, sizeof (NMPlatformIP4Route), count);
		gboolean success;
		gs_unref_array GArray *device_route_purge_list = NULL;

		if (   default_route_metric >= 0
		    && added_addresses) {
			/* For IPv6, we explicitly add the device-routes (onlink) to NMIP6Config.
			 * As we don't do that for IPv4, add it here shortly before syncing
			 * the routes. For NMRouteManager these routes are very much important. */
			for (i = 0; i < added_addresses->len; i++) {
				const NMPlatformIP4Address *addr = added_addresses->pdata[i];
				NMPlatformIP4Route route = { 0 };

				if (addr->plen == 0)
					continue;

				route.ifindex = ifindex;
				route.source = NM_IP_CONFIG_SOURCE_KERNEL;
				route.network = nm_utils_ip4_address_clear_host_address (addr->address, addr->plen);
				route.plen = addr->plen;
				route.pref_src = addr->address;
				route.metric = default_route_metric;

				g_array_append_val (routes, route);

				if (default_route_metric != NM_PLATFORM_ROUTE_METRIC_IP4_DEVICE_ROUTE) {
					if (!device_route_purge_list)
						device_route_purge_list = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP4Route));
					route.metric = NM_PLATFORM_ROUTE_METRIC_IP4_DEVICE_ROUTE;
					g_array_append_val (device_route_purge_list, route);
				}
			}
		}

		for (i = 0; i < count; i++) {
			const NMPlatformIP4Route *route;

			route = nm_ip4_config_get_route (config, i);

			/* Don't add the route if it's more specific than one of the subnets
			 * the device already has an IP address on.
			 */
			if (   route->gateway == 0
			    && nm_ip4_config_destination_is_direct (config, route->network, route->plen))
				continue;

			/* duplicates in @routes are no problem as route-manager handles them
			 * gracefully (by ignoring them). */
			g_array_append_vals (routes, route, 1);
		}

		nm_route_manager_ip4_route_register_device_route_purge_list (nm_route_manager_get (), device_route_purge_list);

		success = nm_route_manager_ip4_route_sync (nm_route_manager_get (), ifindex, routes, default_route_metric < 0, routes_full_sync);
		g_array_unref (routes);
		if (!success)
			return FALSE;
	}

	return TRUE;
}

void
nm_ip4_config_merge_setting (NMIP4Config *config, NMSettingIPConfig *setting, guint32 default_route_metric)
{
	NMIP4ConfigPrivate *priv;
	guint naddresses, nroutes, nnameservers, nsearches;
	int i;

	if (!setting)
		return;

	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_object_freeze_notify (G_OBJECT (config));

	naddresses = nm_setting_ip_config_get_num_addresses (setting);
	nroutes = nm_setting_ip_config_get_num_routes (setting);
	nnameservers = nm_setting_ip_config_get_num_dns (setting);
	nsearches = nm_setting_ip_config_get_num_dns_searches (setting);

	/* Gateway */
	if (nm_setting_ip_config_get_never_default (setting))
		nm_ip4_config_set_never_default (config, TRUE);
	else if (nm_setting_ip_config_get_ignore_auto_routes (setting))
		nm_ip4_config_set_never_default (config, FALSE);
	if (nm_setting_ip_config_get_gateway (setting)) {
		guint32 gateway;

		inet_pton (AF_INET, nm_setting_ip_config_get_gateway (setting), &gateway);
		nm_ip4_config_set_gateway (config, gateway);
	}

	if (priv->route_metric  == -1)
		priv->route_metric = nm_setting_ip_config_get_route_metric (setting);

	/* Addresses */
	for (i = 0; i < naddresses; i++) {
		NMIPAddress *s_addr = nm_setting_ip_config_get_address (setting, i);
		GVariant *label;
		NMPlatformIP4Address address;

		memset (&address, 0, sizeof (address));
		nm_ip_address_get_address_binary (s_addr, &address.address);
		address.plen = nm_ip_address_get_prefix (s_addr);
		address.lifetime = NM_PLATFORM_LIFETIME_PERMANENT;
		address.preferred = NM_PLATFORM_LIFETIME_PERMANENT;
		address.source = NM_IP_CONFIG_SOURCE_USER;

		label = nm_ip_address_get_attribute (s_addr, "label");
		if (label)
			g_strlcpy (address.label, g_variant_get_string (label, NULL), sizeof (address.label));

		nm_ip4_config_add_address (config, &address);
	}

	/* Routes */
	if (nm_setting_ip_config_get_ignore_auto_routes (setting))
		nm_ip4_config_reset_routes (config);
	for (i = 0; i < nroutes; i++) {
		NMIPRoute *s_route = nm_setting_ip_config_get_route (setting, i);
		NMPlatformIP4Route route;

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

		nm_ip4_config_add_route (config, &route);
	}

	/* DNS */
	if (nm_setting_ip_config_get_ignore_auto_dns (setting)) {
		nm_ip4_config_reset_nameservers (config);
		nm_ip4_config_reset_domains (config);
		nm_ip4_config_reset_searches (config);
	}
	for (i = 0; i < nnameservers; i++) {
		guint32 ip;

		if (inet_pton (AF_INET, nm_setting_ip_config_get_dns (setting, i), &ip) == 1)
			nm_ip4_config_add_nameserver (config, ip);
	}
	for (i = 0; i < nsearches; i++)
		nm_ip4_config_add_search (config, nm_setting_ip_config_get_dns_search (setting, i));

	i = 0;
	while ((i = nm_setting_ip_config_next_valid_dns_option (setting, i)) >= 0) {
		nm_ip4_config_add_dns_option (config, nm_setting_ip_config_get_dns_option (setting, i));
		i++;
	}

	g_object_thaw_notify (G_OBJECT (config));
}

NMSetting *
nm_ip4_config_create_setting (const NMIP4Config *config)
{
	NMSettingIPConfig *s_ip4;
	guint32 gateway;
	guint naddresses, nroutes, nnameservers, nsearches, noptions;
	const char *method = NULL;
	int i;
	gint64 route_metric;

	s_ip4 = NM_SETTING_IP_CONFIG (nm_setting_ip4_config_new ());

	if (!config) {
		g_object_set (s_ip4,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
		              NULL);
		return NM_SETTING (s_ip4);
	}

	gateway = nm_ip4_config_get_gateway (config);
	naddresses = nm_ip4_config_get_num_addresses (config);
	nroutes = nm_ip4_config_get_num_routes (config);
	nnameservers = nm_ip4_config_get_num_nameservers (config);
	nsearches = nm_ip4_config_get_num_searches (config);
	noptions = nm_ip4_config_get_num_dns_options (config);
	route_metric = nm_ip4_config_get_route_metric (config);

	/* Addresses */
	for (i = 0; i < naddresses; i++) {
		const NMPlatformIP4Address *address = nm_ip4_config_get_address (config, i);
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
			nm_ip_address_set_attribute (s_addr, "label", g_variant_new_string (address->label));

		nm_setting_ip_config_add_address (s_ip4, s_addr);
		nm_ip_address_unref (s_addr);
	}

	/* Gateway */
	if (   nm_ip4_config_has_gateway (config)
	    && nm_setting_ip_config_get_num_addresses (s_ip4) > 0) {
		g_object_set (s_ip4,
		              NM_SETTING_IP_CONFIG_GATEWAY, nm_utils_inet4_ntop (gateway, NULL),
		              NULL);
	}

	/* Use 'disabled' if the method wasn't previously set */
	if (!method)
		method = NM_SETTING_IP4_CONFIG_METHOD_DISABLED;

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, method,
	              NM_SETTING_IP_CONFIG_ROUTE_METRIC, (gint64) route_metric,
	              NULL);

	/* Routes */
	for (i = 0; i < nroutes; i++) {
		const NMPlatformIP4Route *route = nm_ip4_config_get_route (config, i);
		NMIPRoute *s_route;

		/* Ignore default route. */
		if (!route->plen)
			continue;

		/* Ignore routes provided by external sources */
		if (route->source != NM_IP_CONFIG_SOURCE_USER)
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
		guint32 nameserver = nm_ip4_config_get_nameserver (config, i);

		nm_setting_ip_config_add_dns (s_ip4, nm_utils_inet4_ntop (nameserver, NULL));
	}
	for (i = 0; i < nsearches; i++) {
		const char *search = nm_ip4_config_get_search (config, i);

		nm_setting_ip_config_add_dns_search (s_ip4, search);
	}

	for (i = 0; i < noptions; i++) {
		const char *option = nm_ip4_config_get_dns_option (config, i);

		nm_setting_ip_config_add_dns_option (s_ip4, option);
	}

	return NM_SETTING (s_ip4);
}

/******************************************************************/

void
nm_ip4_config_merge (NMIP4Config *dst, const NMIP4Config *src, NMIPConfigMergeFlags merge_flags)
{
	NMIP4ConfigPrivate *dst_priv, *src_priv;
	guint32 i;

	g_return_if_fail (src != NULL);
	g_return_if_fail (dst != NULL);

	dst_priv = NM_IP4_CONFIG_GET_PRIVATE (dst);
	src_priv = NM_IP4_CONFIG_GET_PRIVATE (src);

	g_object_freeze_notify (G_OBJECT (dst));

	/* addresses */
	for (i = 0; i < nm_ip4_config_get_num_addresses (src); i++)
		nm_ip4_config_add_address (dst, nm_ip4_config_get_address (src, i));

	/* nameservers */
	if (!NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_DNS)) {
		for (i = 0; i < nm_ip4_config_get_num_nameservers (src); i++)
			nm_ip4_config_add_nameserver (dst, nm_ip4_config_get_nameserver (src, i));
	}

	/* default gateway */
	if (nm_ip4_config_has_gateway (src))
		nm_ip4_config_set_gateway (dst, nm_ip4_config_get_gateway (src));

	/* routes */
	if (!NM_FLAGS_HAS (merge_flags, NM_IP_CONFIG_MERGE_NO_ROUTES)) {
		for (i = 0; i < nm_ip4_config_get_num_routes (src); i++)
			nm_ip4_config_add_route (dst, nm_ip4_config_get_route (src, i));
	}

	if (dst_priv->route_metric == -1)
		dst_priv->route_metric = src_priv->route_metric;
	else if (src_priv->route_metric != -1)
		dst_priv->route_metric = MIN (dst_priv->route_metric, src_priv->route_metric);

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

	/* MSS */
	if (nm_ip4_config_get_mss (src))
		nm_ip4_config_set_mss (dst, nm_ip4_config_get_mss (src));

	/* MTU */
	if (nm_ip4_config_get_mtu (src))
		nm_ip4_config_set_mtu (dst, nm_ip4_config_get_mtu (src),
		                       nm_ip4_config_get_mtu_source (src));

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

	g_object_thaw_notify (G_OBJECT (dst));
}

/*******************************************************************************/

static int
_addresses_get_index (const NMIP4Config *self, const NMPlatformIP4Address *addr)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->addresses->len; i++) {
		const NMPlatformIP4Address *a = &g_array_index (priv->addresses, NMPlatformIP4Address, i);

		if (addresses_are_duplicate (addr, a))
			return (int) i;
	}
	return -1;
}

static int
_nameservers_get_index (const NMIP4Config *self, guint32 ns)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->nameservers->len; i++) {
		guint32 n = g_array_index (priv->nameservers, guint32, i);

		if (ns == n)
			return (int) i;
	}
	return -1;
}

static int
_routes_get_index (const NMIP4Config *self, const NMPlatformIP4Route *route)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->routes->len; i++) {
		const NMPlatformIP4Route *r = &g_array_index (priv->routes, NMPlatformIP4Route, i);

		if (   route->network == r->network
		    && route->plen == r->plen)
			return (int) i;
	}
	return -1;
}

static int
_domains_get_index (const NMIP4Config *self, const char *domain)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
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
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
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
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
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
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
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
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);
	guint i;

	for (i = 0; i < priv->wins->len; i++) {
		guint32 n = g_array_index (priv->wins, guint32, i);

		if (n == wins_server)
			return (int) i;
	}
	return -1;
}

/*******************************************************************************/

/**
 * nm_ip4_config_subtract:
 * @dst: config from which to remove everything in @src
 * @src: config to remove from @dst
 *
 * Removes everything in @src from @dst.
 */
void
nm_ip4_config_subtract (NMIP4Config *dst, const NMIP4Config *src)
{
	guint32 i;
	gint idx;

	g_return_if_fail (src != NULL);
	g_return_if_fail (dst != NULL);

	g_object_freeze_notify (G_OBJECT (dst));

	/* addresses */
	for (i = 0; i < nm_ip4_config_get_num_addresses (src); i++) {
		idx = _addresses_get_index (dst, nm_ip4_config_get_address (src, i));
		if (idx >= 0)
			nm_ip4_config_del_address (dst, idx);
	}

	/* nameservers */
	for (i = 0; i < nm_ip4_config_get_num_nameservers (src); i++) {
		idx = _nameservers_get_index (dst, nm_ip4_config_get_nameserver (src, i));
		if (idx >= 0)
			nm_ip4_config_del_nameserver (dst, idx);
	}

	/* default gateway */
	if (   (nm_ip4_config_has_gateway (src) == nm_ip4_config_has_gateway (dst))
	    && (nm_ip4_config_get_gateway (src) == nm_ip4_config_get_gateway (dst)))
		nm_ip4_config_unset_gateway (dst);

	if (!nm_ip4_config_get_num_addresses (dst))
		nm_ip4_config_unset_gateway (dst);

	/* ignore route_metric */

	/* routes */
	for (i = 0; i < nm_ip4_config_get_num_routes (src); i++) {
		idx = _routes_get_index (dst, nm_ip4_config_get_route (src, i));
		if (idx >= 0)
			nm_ip4_config_del_route (dst, idx);
	}

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

	/* MSS */
	if (nm_ip4_config_get_mss (src) == nm_ip4_config_get_mss (dst))
		nm_ip4_config_set_mss (dst, 0);

	/* MTU */
	if (nm_ip4_config_get_mtu (src) == nm_ip4_config_get_mtu (dst))
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

	g_object_thaw_notify (G_OBJECT (dst));
}

void
nm_ip4_config_intersect (NMIP4Config *dst, const NMIP4Config *src)
{
	guint32 i;
	gint idx;

	g_return_if_fail (src != NULL);
	g_return_if_fail (dst != NULL);

	g_object_freeze_notify (G_OBJECT (dst));

	/* addresses */
	for (i = 0; i < nm_ip4_config_get_num_addresses (dst); ) {
		idx = _addresses_get_index (src, nm_ip4_config_get_address (dst, i));
		if (idx < 0)
			nm_ip4_config_del_address (dst, i);
		else
			i++;
	}

	/* ignore route_metric */
	/* ignore nameservers */

	/* default gateway */
	if (   !nm_ip4_config_get_num_addresses (dst)
	    || (nm_ip4_config_has_gateway (src) != nm_ip4_config_has_gateway (dst))
	    || (nm_ip4_config_get_gateway (src) != nm_ip4_config_get_gateway (dst))) {
		nm_ip4_config_unset_gateway (dst);
	}

	/* routes */
	for (i = 0; i < nm_ip4_config_get_num_routes (dst); ) {
		idx = _routes_get_index (src, nm_ip4_config_get_route (dst, i));
		if (idx < 0)
			nm_ip4_config_del_route (dst, i);
		else
			i++;
	}

	/* ignore domains */
	/* ignore dns searches */
	/* ignore dns options */
	/* ignore NIS */
	/* ignore WINS */

	g_object_thaw_notify (G_OBJECT (dst));
}


/**
 * nm_ip4_config_replace:
 * @dst: config from which to remove everything in @src
 * @src: config to remove from @dst
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
	NMIP4ConfigPrivate *dst_priv, *src_priv;
	const NMPlatformIP4Address *dst_addr, *src_addr;
	const NMPlatformIP4Route *dst_route, *src_route;

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

	/* never_default */
	if (src_priv->never_default != dst_priv->never_default) {
		dst_priv->never_default = src_priv->never_default;
		has_minor_changes = TRUE;
	}

	/* default gateway */
	if (   src_priv->gateway != dst_priv->gateway
	    || src_priv->has_gateway != dst_priv->has_gateway) {
		nm_ip4_config_set_gateway (dst, src_priv->gateway);
		has_relevant_changes = TRUE;
	}

	if (src_priv->route_metric != dst_priv->route_metric) {
		dst_priv->route_metric = src_priv->route_metric;
		has_minor_changes = TRUE;
	}

	/* addresses */
	num = nm_ip4_config_get_num_addresses (src);
	are_equal = num == nm_ip4_config_get_num_addresses (dst);
	if (are_equal) {
		for (i = 0; i < num; i++ ) {
			if (nm_platform_ip4_address_cmp (src_addr = nm_ip4_config_get_address (src, i),
			                                 dst_addr = nm_ip4_config_get_address (dst, i))) {
				are_equal = FALSE;
				if (   !addresses_are_duplicate (src_addr, dst_addr)
				    || (nm_platform_ip4_address_get_peer (src_addr) != nm_platform_ip4_address_get_peer (dst_addr))) {
					has_relevant_changes = TRUE;
					break;
				}
			}
		}
	} else
		has_relevant_changes = TRUE;
	if (!are_equal) {
		nm_ip4_config_reset_addresses (dst);
		for (i = 0; i < num; i++)
			nm_ip4_config_add_address (dst, nm_ip4_config_get_address (src, i));
		has_minor_changes = TRUE;
	}

	/* routes */
	num = nm_ip4_config_get_num_routes (src);
	are_equal = num == nm_ip4_config_get_num_routes (dst);
	if (are_equal) {
		for (i = 0; i < num; i++ ) {
			if (nm_platform_ip4_route_cmp (src_route = nm_ip4_config_get_route (src, i),
			                               dst_route = nm_ip4_config_get_route (dst, i))) {
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
		nm_ip4_config_reset_routes (dst);
		for (i = 0; i < num; i++)
			nm_ip4_config_add_route (dst, nm_ip4_config_get_route (src, i));
		has_minor_changes = TRUE;
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

	/* mss */
	if (src_priv->mss != dst_priv->mss) {
		nm_ip4_config_set_mss (dst, src_priv->mss);
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
	if (src_priv->mtu != dst_priv->mtu) {
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
nm_ip4_config_dump (const NMIP4Config *config, const char *detail)
{
	guint32 i, tmp;
	const char *str;

	g_return_if_fail (config != NULL);

	g_message ("--------- NMIP4Config %p (%s)", config, detail);

	str = nm_exported_object_get_path (NM_EXPORTED_OBJECT (config));
	if (str)
		g_message ("   path: %s", str);

	/* addresses */
	for (i = 0; i < nm_ip4_config_get_num_addresses (config); i++)
		g_message ("      a: %s", nm_platform_ip4_address_to_string (nm_ip4_config_get_address (config, i)));

	/* default gateway */
	if (nm_ip4_config_has_gateway (config)) {
		tmp = nm_ip4_config_get_gateway (config);
		g_message ("     gw: %s", nm_utils_inet4_ntop (tmp, NULL));
	}

	/* nameservers */
	for (i = 0; i < nm_ip4_config_get_num_nameservers (config); i++) {
		tmp = nm_ip4_config_get_nameserver (config, i);
		g_message ("     ns: %s", nm_utils_inet4_ntop (tmp, NULL));
	}

	/* routes */
	for (i = 0; i < nm_ip4_config_get_num_routes (config); i++)
		g_message ("     rt: %s", nm_platform_ip4_route_to_string (nm_ip4_config_get_route (config, i)));

	/* domains */
	for (i = 0; i < nm_ip4_config_get_num_domains (config); i++)
		g_message (" domain: %s", nm_ip4_config_get_domain (config, i));

	/* dns searches */
	for (i = 0; i < nm_ip4_config_get_num_searches (config); i++)
		g_message (" search: %s", nm_ip4_config_get_search (config, i));

	/* dns options */
	for (i = 0; i < nm_ip4_config_get_num_dns_options (config); i++)
		g_message (" dnsopt: %s", nm_ip4_config_get_dns_option (config, i));


	g_message ("    mss: %"G_GUINT32_FORMAT, nm_ip4_config_get_mss (config));
	g_message ("    mtu: %"G_GUINT32_FORMAT, nm_ip4_config_get_mtu (config));

	/* NIS */
	for (i = 0; i < nm_ip4_config_get_num_nis_servers (config); i++) {
		tmp = nm_ip4_config_get_nis_server (config, i);
		g_message ("    nis: %s", nm_utils_inet4_ntop (tmp, NULL));
	}

	g_message (" nisdmn: %s", str_if_set (nm_ip4_config_get_nis_domain (config), "(none)"));

	/* WINS */
	for (i = 0; i < nm_ip4_config_get_num_wins (config); i++) {
		tmp = nm_ip4_config_get_wins (config, i);
		g_message ("   wins: %s", nm_utils_inet4_ntop (tmp, NULL));
	}

	g_message (" n-dflt: %d", nm_ip4_config_get_never_default (config));
	g_message (" mtrd:   %d", (int) nm_ip4_config_get_metered (config));
}

gboolean
nm_ip4_config_destination_is_direct (const NMIP4Config *config, guint32 network, int plen)
{
	guint naddresses = nm_ip4_config_get_num_addresses (config);
	int i;

	for (i = 0; i < naddresses; i++) {
		const NMPlatformIP4Address *item = nm_ip4_config_get_address (config, i);

		if (item->plen <= plen && same_prefix (item->address, network, item->plen))
			return TRUE;
	}

	return FALSE;
}

/******************************************************************/

void
nm_ip4_config_set_never_default (NMIP4Config *config, gboolean never_default)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	priv->never_default = !!never_default;
}

gboolean
nm_ip4_config_get_never_default (const NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->never_default;
}

void
nm_ip4_config_set_gateway (NMIP4Config *config, guint32 gateway)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	if (priv->gateway != gateway || !priv->has_gateway) {
		priv->gateway = gateway;
		priv->has_gateway = TRUE;
		_NOTIFY (config, PROP_GATEWAY);
	}
}

void
nm_ip4_config_unset_gateway (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	if (priv->has_gateway) {
		priv->gateway = 0;
		priv->has_gateway = FALSE;
		_NOTIFY (config, PROP_GATEWAY);
	}
}

gboolean
nm_ip4_config_has_gateway (const NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->has_gateway;
}

guint32
nm_ip4_config_get_gateway (const NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->gateway;
}

gint64
nm_ip4_config_get_route_metric (const NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->route_metric;
}

/******************************************************************/

void
nm_ip4_config_reset_addresses (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	if (priv->addresses->len != 0) {
		g_array_set_size (priv->addresses, 0);
		_NOTIFY (config, PROP_ADDRESS_DATA);
		_NOTIFY (config, PROP_ADDRESSES);
	}
}

/**
 * nm_ip4_config_add_address:
 * @config: the #NMIP4Config
 * @new: the new address to add to @config
 *
 * Adds the new address to @config.  If an address with the same basic properties
 * (address, prefix) already exists in @config, it is overwritten with the
 * lifetime and preferred of @new.  The source is also overwritten by the source
 * from @new if that source is higher priority.
 */
void
nm_ip4_config_add_address (NMIP4Config *config, const NMPlatformIP4Address *new)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	NMPlatformIP4Address item_old;
	int i;

	g_return_if_fail (new != NULL);

	for (i = 0; i < priv->addresses->len; i++ ) {
		NMPlatformIP4Address *item = &g_array_index (priv->addresses, NMPlatformIP4Address, i);

		if (addresses_are_duplicate (item, new)) {
			if (nm_platform_ip4_address_cmp (item, new) == 0)
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
			if (nm_platform_ip4_address_cmp (&item_old, item) == 0)
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
nm_ip4_config_del_address (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->addresses->len);

	g_array_remove_index (priv->addresses, i);
	_NOTIFY (config, PROP_ADDRESS_DATA);
	_NOTIFY (config, PROP_ADDRESSES);
}

guint
nm_ip4_config_get_num_addresses (const NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->addresses->len;
}

const NMPlatformIP4Address *
nm_ip4_config_get_address (const NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return &g_array_index (priv->addresses, NMPlatformIP4Address, i);
}

gboolean
nm_ip4_config_address_exists (const NMIP4Config *config,
                              const NMPlatformIP4Address *needle)
{
	return _addresses_get_index (config, needle) >= 0;
}

/******************************************************************/

void
nm_ip4_config_reset_routes (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	if (priv->routes->len != 0) {
		g_array_set_size (priv->routes, 0);
		_NOTIFY (config, PROP_ROUTE_DATA);
		_NOTIFY (config, PROP_ROUTES);
	}
}

/**
 * nm_ip4_config_add_route:
 * @config: the #NMIP4Config
 * @new: the new route to add to @config
 *
 * Adds the new route to @config.  If a route with the same basic properties
 * (network, prefix) already exists in @config, it is overwritten including the
 * gateway and metric of @new.  The source is also overwritten by the source
 * from @new if that source is higher priority.
 */
void
nm_ip4_config_add_route (NMIP4Config *config, const NMPlatformIP4Route *new)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	NMIPConfigSource old_source;
	int i;

	g_return_if_fail (new != NULL);
	g_return_if_fail (new->plen > 0);
	g_assert (priv->ifindex);

	for (i = 0; i < priv->routes->len; i++ ) {
		NMPlatformIP4Route *item = &g_array_index (priv->routes, NMPlatformIP4Route, i);

		if (routes_are_duplicate (item, new, FALSE)) {
			if (nm_platform_ip4_route_cmp (item, new) == 0)
				return;
			old_source = item->source;
			memcpy (item, new, sizeof (*item));
			/* Restore highest priority source */
			item->source = MAX (old_source, new->source);
			item->ifindex = priv->ifindex;
			goto NOTIFY;
		}
	}

	g_array_append_val (priv->routes, *new);
	g_array_index (priv->routes, NMPlatformIP4Route, priv->routes->len - 1).ifindex = priv->ifindex;
NOTIFY:
	_NOTIFY (config, PROP_ROUTE_DATA);
	_NOTIFY (config, PROP_ROUTES);
}

void
nm_ip4_config_del_route (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->routes->len);

	g_array_remove_index (priv->routes, i);
	_NOTIFY (config, PROP_ROUTE_DATA);
	_NOTIFY (config, PROP_ROUTES);
}

guint
nm_ip4_config_get_num_routes (const NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->routes->len;
}

const NMPlatformIP4Route *
nm_ip4_config_get_route (const NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return &g_array_index (priv->routes, NMPlatformIP4Route, i);
}

const NMPlatformIP4Route *
nm_ip4_config_get_direct_route_for_host (const NMIP4Config *config, guint32 host)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	guint i;
	NMPlatformIP4Route *best_route = NULL;

	g_return_val_if_fail (host, NULL);

	for (i = 0; i < priv->routes->len; i++) {
		NMPlatformIP4Route *item = &g_array_index (priv->routes, NMPlatformIP4Route, i);

		if (item->gateway != 0)
			continue;

		if (best_route && best_route->plen > item->plen)
			continue;

		if (nm_utils_ip4_address_clear_host_address (host, item->plen) != nm_utils_ip4_address_clear_host_address (item->network, item->plen))
			continue;

		if (best_route && best_route->metric <= item->metric)
			continue;

		best_route = item;
	}

	return best_route;
}

const NMPlatformIP4Address *
nm_ip4_config_get_subnet_for_host (const NMIP4Config *config, guint32 host)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	guint i;
	NMPlatformIP4Address *subnet = NULL;

	g_return_val_if_fail (host, NULL);

	for (i = 0; i < priv->addresses->len; i++) {
		NMPlatformIP4Address *item = &g_array_index (priv->addresses, NMPlatformIP4Address, i);

		if (subnet && subnet->plen >= item->plen)
			continue;
		if (nm_utils_ip4_address_clear_host_address (host, item->plen) != nm_utils_ip4_address_clear_host_address (item->address, item->plen))
			continue;
		subnet = item;
	}

	return subnet;
}

/******************************************************************/

void
nm_ip4_config_reset_nameservers (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	if (priv->nameservers->len != 0) {
		g_array_set_size (priv->nameservers, 0);
		_NOTIFY (config, PROP_NAMESERVERS);
	}
}

void
nm_ip4_config_add_nameserver (NMIP4Config *config, guint32 new)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	int i;

	g_return_if_fail (new != 0);

	for (i = 0; i < priv->nameservers->len; i++)
		if (new == g_array_index (priv->nameservers, guint32, i))
			return;

	g_array_append_val (priv->nameservers, new);
	_NOTIFY (config, PROP_NAMESERVERS);
}

void
nm_ip4_config_del_nameserver (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->nameservers->len);

	g_array_remove_index (priv->nameservers, i);
	_NOTIFY (config, PROP_NAMESERVERS);
}

guint32
nm_ip4_config_get_num_nameservers (const NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->nameservers->len;
}

guint32
nm_ip4_config_get_nameserver (const NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return g_array_index (priv->nameservers, guint32, i);
}

/******************************************************************/

void
nm_ip4_config_reset_domains (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	if (priv->domains->len != 0) {
		g_ptr_array_set_size (priv->domains, 0);
		_NOTIFY (config, PROP_DOMAINS);
	}
}

void
nm_ip4_config_add_domain (NMIP4Config *config, const char *domain)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
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
nm_ip4_config_del_domain (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->domains->len);

	g_ptr_array_remove_index (priv->domains, i);
	_NOTIFY (config, PROP_DOMAINS);
}

guint32
nm_ip4_config_get_num_domains (const NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->domains->len;
}

const char *
nm_ip4_config_get_domain (const NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return g_ptr_array_index (priv->domains, i);
}

/******************************************************************/

void
nm_ip4_config_reset_searches (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	if (priv->searches->len != 0) {
		g_ptr_array_set_size (priv->searches, 0);
		_NOTIFY (config, PROP_SEARCHES);
	}
}

void
nm_ip4_config_add_search (NMIP4Config *config, const char *new)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
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
nm_ip4_config_del_search (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->searches->len);

	g_ptr_array_remove_index (priv->searches, i);
	_NOTIFY (config, PROP_SEARCHES);
}

guint32
nm_ip4_config_get_num_searches (const NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->searches->len;
}

const char *
nm_ip4_config_get_search (const NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return g_ptr_array_index (priv->searches, i);
}

/******************************************************************/

void
nm_ip4_config_reset_dns_options (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	if (priv->dns_options->len != 0) {
		g_ptr_array_set_size (priv->dns_options, 0);
		_NOTIFY (config, PROP_DNS_OPTIONS);
	}
}

void
nm_ip4_config_add_dns_option (NMIP4Config *config, const char *new)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
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
nm_ip4_config_del_dns_option(NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->dns_options->len);

	g_ptr_array_remove_index (priv->dns_options, i);
	_NOTIFY (config, PROP_DNS_OPTIONS);
}

guint32
nm_ip4_config_get_num_dns_options (const NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->dns_options->len;
}

const char *
nm_ip4_config_get_dns_option (const NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return g_ptr_array_index (priv->dns_options, i);
}

/******************************************************************/

void
nm_ip4_config_set_mss (NMIP4Config *config, guint32 mss)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	priv->mss = mss;
}

guint32
nm_ip4_config_get_mss (const NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->mss;
}

/******************************************************************/

void
nm_ip4_config_reset_nis_servers (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_array_set_size (priv->nis, 0);
}

void
nm_ip4_config_add_nis_server (NMIP4Config *config, guint32 nis)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	int i;

	for (i = 0; i < priv->nis->len; i++)
		if (nis == g_array_index (priv->nis, guint32, i))
			return;

	g_array_append_val (priv->nis, nis);
}

void
nm_ip4_config_del_nis_server (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->nis->len);

	g_array_remove_index (priv->nis, i);
}

guint32
nm_ip4_config_get_num_nis_servers (const NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->nis->len;
}

guint32
nm_ip4_config_get_nis_server (const NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return g_array_index (priv->nis, guint32, i);
}

void
nm_ip4_config_set_nis_domain (NMIP4Config *config, const char *domain)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_free (priv->nis_domain);
	priv->nis_domain = g_strdup (domain);
}

const char *
nm_ip4_config_get_nis_domain (const NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->nis_domain;
}

/******************************************************************/

void
nm_ip4_config_reset_wins (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	if (priv->wins->len != 0) {
		g_array_set_size (priv->wins, 0);
		_NOTIFY (config, PROP_WINS_SERVERS);
	}
}

void
nm_ip4_config_add_wins (NMIP4Config *config, guint32 wins)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	int i;

	g_return_if_fail (wins != 0);

	for (i = 0; i < priv->wins->len; i++)
		if (wins == g_array_index (priv->wins, guint32, i))
			return;

	g_array_append_val (priv->wins, wins);
	_NOTIFY (config, PROP_WINS_SERVERS);
}

void
nm_ip4_config_del_wins (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->wins->len);

	g_array_remove_index (priv->wins, i);
	_NOTIFY (config, PROP_WINS_SERVERS);
}

guint32
nm_ip4_config_get_num_wins (const NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->wins->len;
}

guint32
nm_ip4_config_get_wins (const NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return g_array_index (priv->wins, guint32, i);
}

/******************************************************************/

void
nm_ip4_config_set_mtu (NMIP4Config *config, guint32 mtu, NMIPConfigSource source)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	if (source > priv->mtu_source) {
		priv->mtu = mtu;
		priv->mtu_source = source;
	} else if (source == priv->mtu_source && (!priv->mtu || priv->mtu > mtu))
		priv->mtu = mtu;
}

guint32
nm_ip4_config_get_mtu (const NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->mtu;
}

NMIPConfigSource
nm_ip4_config_get_mtu_source (const NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->mtu_source;
}

/******************************************************************/

void
nm_ip4_config_set_metered (NMIP4Config *config, gboolean metered)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	priv->metered = !!metered;
}

gboolean
nm_ip4_config_get_metered (const NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->metered;
}

/******************************************************************/

static inline void
hash_u32 (GChecksum *sum, guint32 n)
{
	g_checksum_update (sum, (const guint8 *) &n, sizeof (n));
}

void
nm_ip4_config_hash (const NMIP4Config *config, GChecksum *sum, gboolean dns_only)
{
	guint32 i;
	const char *s;

	g_return_if_fail (config);
	g_return_if_fail (sum);

	if (!dns_only) {
		hash_u32 (sum, nm_ip4_config_has_gateway (config));
		hash_u32 (sum, nm_ip4_config_get_gateway (config));

		for (i = 0; i < nm_ip4_config_get_num_addresses (config); i++) {
			const NMPlatformIP4Address *address = nm_ip4_config_get_address (config, i);
			hash_u32 (sum, address->address);
			hash_u32 (sum, address->plen);
			hash_u32 (sum, nm_platform_ip4_address_get_peer_net (address));
		}

		for (i = 0; i < nm_ip4_config_get_num_routes (config); i++) {
			const NMPlatformIP4Route *route = nm_ip4_config_get_route (config, i);

			hash_u32 (sum, route->network);
			hash_u32 (sum, route->plen);
			hash_u32 (sum, route->gateway);
			hash_u32 (sum, route->metric);
		}

		for (i = 0; i < nm_ip4_config_get_num_nis_servers (config); i++)
			hash_u32 (sum, nm_ip4_config_get_nis_server (config, i));

		s = nm_ip4_config_get_nis_domain (config);
		if (s)
			g_checksum_update (sum, (const guint8 *) s, strlen (s));
	}

	for (i = 0; i < nm_ip4_config_get_num_nameservers (config); i++)
		hash_u32 (sum, nm_ip4_config_get_nameserver (config, i));

	for (i = 0; i < nm_ip4_config_get_num_wins (config); i++)
		hash_u32 (sum, nm_ip4_config_get_wins (config, i));

	for (i = 0; i < nm_ip4_config_get_num_domains (config); i++) {
		s = nm_ip4_config_get_domain (config, i);
		g_checksum_update (sum, (const guint8 *) s, strlen (s));
	}

	for (i = 0; i < nm_ip4_config_get_num_searches (config); i++) {
		s = nm_ip4_config_get_search (config, i);
		g_checksum_update (sum, (const guint8 *) s, strlen (s));
	}

	for (i = 0; i < nm_ip4_config_get_num_dns_options (config); i++) {
		s = nm_ip4_config_get_dns_option (config, i);
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
	gsize a_len = g_checksum_type_get_length (G_CHECKSUM_SHA1);
	gsize b_len = g_checksum_type_get_length (G_CHECKSUM_SHA1);
	guchar a_data[a_len], b_data[b_len];
	gboolean equal;

	if (a)
		nm_ip4_config_hash (a, a_checksum, FALSE);
	if (b)
		nm_ip4_config_hash (b, b_checksum, FALSE);

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
nm_ip4_config_init (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	priv->addresses = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP4Address));
	priv->routes = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP4Route));
	priv->nameservers = g_array_new (FALSE, FALSE, sizeof (guint32));
	priv->domains = g_ptr_array_new_with_free_func (g_free);
	priv->searches = g_ptr_array_new_with_free_func (g_free);
	priv->dns_options = g_ptr_array_new_with_free_func (g_free);
	priv->nis = g_array_new (FALSE, TRUE, sizeof (guint32));
	priv->wins = g_array_new (FALSE, TRUE, sizeof (guint32));
	priv->route_metric = -1;
}

static void
finalize (GObject *object)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (object);

	g_array_unref (priv->addresses);
	g_array_unref (priv->routes);
	g_array_unref (priv->nameservers);
	g_ptr_array_unref (priv->domains);
	g_ptr_array_unref (priv->searches);
	g_ptr_array_unref (priv->dns_options);
	g_array_unref (priv->nis);
	g_free (priv->nis_domain);
	g_array_unref (priv->wins);

	G_OBJECT_CLASS (nm_ip4_config_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMIP4Config *config = NM_IP4_CONFIG (object);
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_IFINDEX:
		g_value_set_int (value, priv->ifindex);
		break;
	case PROP_ADDRESS_DATA:
		{
			GVariantBuilder array_builder, addr_builder;
			int naddr = nm_ip4_config_get_num_addresses (config);
			int i;

			g_variant_builder_init (&array_builder, G_VARIANT_TYPE ("aa{sv}"));
			for (i = 0; i < naddr; i++) {
				const NMPlatformIP4Address *address = nm_ip4_config_get_address (config, i);

				g_variant_builder_init (&addr_builder, G_VARIANT_TYPE ("a{sv}"));
				g_variant_builder_add (&addr_builder, "{sv}",
				                       "address",
				                       g_variant_new_string (nm_utils_inet4_ntop (address->address, NULL)));
				g_variant_builder_add (&addr_builder, "{sv}",
				                       "prefix",
				                       g_variant_new_uint32 (address->plen));
				if (   address->peer_address
				    && address->peer_address != address->address) {
					g_variant_builder_add (&addr_builder, "{sv}",
					                       "peer",
					                       g_variant_new_string (nm_utils_inet4_ntop (address->peer_address, NULL)));
				}

				if (*address->label) {
					g_variant_builder_add (&addr_builder, "{sv}",
					                       "label",
					                       g_variant_new_string (address->label));
				}

				g_variant_builder_add (&array_builder, "a{sv}", &addr_builder);
			}

			g_value_take_variant (value, g_variant_builder_end (&array_builder));
		}
		break;
	case PROP_ADDRESSES:
		{
			GVariantBuilder array_builder;
			int naddr = nm_ip4_config_get_num_addresses (config);
			int i;

			g_variant_builder_init (&array_builder, G_VARIANT_TYPE ("aau"));
			for (i = 0; i < naddr; i++) {
				const NMPlatformIP4Address *address = nm_ip4_config_get_address (config, i);
				guint32 dbus_addr[3];

				dbus_addr[0] = address->address;
				dbus_addr[1] = address->plen;
				dbus_addr[2] = i == 0 ? priv->gateway : 0;

				g_variant_builder_add (&array_builder, "@au",
				                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
				                                                  dbus_addr, 3, sizeof (guint32)));
			}

			g_value_take_variant (value, g_variant_builder_end (&array_builder));
		}
		break;
	case PROP_ROUTE_DATA:
		{
			GVariantBuilder array_builder, route_builder;
			guint nroutes = nm_ip4_config_get_num_routes (config);
			int i;

			g_variant_builder_init (&array_builder, G_VARIANT_TYPE ("aa{sv}"));
			for (i = 0; i < nroutes; i++) {
				const NMPlatformIP4Route *route = nm_ip4_config_get_route (config, i);

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

				g_variant_builder_add (&array_builder, "a{sv}", &route_builder);
			}

			g_value_take_variant (value, g_variant_builder_end (&array_builder));
		}
		break;
	case PROP_ROUTES:
		{
			GVariantBuilder array_builder;
			guint nroutes = nm_ip4_config_get_num_routes (config);
			int i;

			g_variant_builder_init (&array_builder, G_VARIANT_TYPE ("aau"));
			for (i = 0; i < nroutes; i++) {
				const NMPlatformIP4Route *route = nm_ip4_config_get_route (config, i);
				guint32 dbus_route[4];

				/* legacy versions of nm_ip4_route_set_prefix() in libnm-util assert that the
				 * plen is positive. Skip the default routes not to break older clients. */
				if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT (route))
					continue;

				dbus_route[0] = route->network;
				dbus_route[1] = route->plen;
				dbus_route[2] = route->gateway;
				dbus_route[3] = route->metric;

				g_variant_builder_add (&array_builder, "@au",
				                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
				                                                  dbus_route, 4, sizeof (guint32)));
			}

			g_value_take_variant (value, g_variant_builder_end (&array_builder));
		}
		break;
	case PROP_GATEWAY:
		if (priv->has_gateway)
			g_value_set_string (value, nm_utils_inet4_ntop (priv->gateway, NULL));
		else
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
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (object);

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
nm_ip4_config_class_init (NMIP4ConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMIP4ConfigPrivate));

	exported_object_class->export_path = NM_DBUS_PATH "/IP4Config/%u";

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize = finalize;

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

	obj_properties[PROP_WINS_SERVERS] =
		g_param_spec_variant (NM_IP4_CONFIG_WINS_SERVERS, "", "",
		                      G_VARIANT_TYPE ("au"),
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, LAST_PROP, obj_properties);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (config_class),
	                                        NMDBUS_TYPE_IP4_CONFIG_SKELETON,
	                                        NULL);
}
