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
 * Copyright (C) 2005 - 2013 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include <string.h>

#include "nm-ip4-config.h"

#include "gsystem-local-alloc.h"
#include "nm-platform.h"
#include "nm-utils.h"
#include "nm-dbus-manager.h"
#include "nm-dbus-glib-types.h"
#include "nm-ip4-config-glue.h"


G_DEFINE_TYPE (NMIP4Config, nm_ip4_config, G_TYPE_OBJECT)

#define NM_IP4_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IP4_CONFIG, NMIP4ConfigPrivate))

typedef struct {
	char *path;

	gboolean never_default;
	guint32 gateway;
	GArray *addresses;
	GSList *routes;
	GArray *nameservers;
	GPtrArray *domains;
	GPtrArray *searches;
	guint32 mss;
	guint32 ptp_address;
	GArray *nis;
	char *nis_domain;
	GArray *wins;
	guint32 mtu;
} NMIP4ConfigPrivate;


enum {
	PROP_0,
	PROP_ADDRESSES,
	PROP_NAMESERVERS,
	PROP_DOMAINS,
	PROP_ROUTES,
	PROP_WINS_SERVERS,

	LAST_PROP
};


NMIP4Config *
nm_ip4_config_new (void)
{
	return (NMIP4Config *) g_object_new (NM_TYPE_IP4_CONFIG, NULL);
}


void
nm_ip4_config_export (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	static guint32 counter = 0;

	if (!priv->path) {
		priv->path = g_strdup_printf (NM_DBUS_PATH "/IP4Config/%d", counter++);
		nm_dbus_manager_register_object (nm_dbus_manager_get (), priv->path, config);
	}
}

const char *
nm_ip4_config_get_dbus_path (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->path;
}

static gboolean
same_prefix (guint32 address1, guint32 address2, int plen)
{
	guint32 masked1 = ntohl (address1) >> (32 - plen);
	guint32 masked2 = ntohl (address2) >> (32 - plen);

	return masked1 == masked2;
}

/******************************************************************/

NMIP4Config *
nm_ip4_config_capture (int ifindex)
{
	NMIP4Config *config = nm_ip4_config_new ();
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	GArray *routes_array;
	NMPlatformIP4Route *routes;
	NMIP4Route *route;
	int i;

	g_array_unref (priv->addresses);
	priv->addresses = nm_platform_ip4_address_get_all (ifindex);

	/* Require at least one IP address. */
	if (!priv->addresses->len) {
		g_object_unref (config);
		return NULL;
	}

	routes_array = nm_platform_ip4_route_get_all (ifindex);
	routes = (NMPlatformIP4Route *)routes_array->data;
	for (i = 0; i < routes_array->len; i++) {
		/* Default route ignored; it's handled internally by NM and not
		 * tracked in the device's IP config.
		 */
		if (routes[i].plen == 0)
			continue;

		route = nm_ip4_route_new ();
		nm_ip4_route_set_dest (route, routes[i].network);
		nm_ip4_route_set_prefix (route, routes[i].plen);
		nm_ip4_route_set_next_hop (route, routes[i].gateway);
		nm_ip4_route_set_metric (route, routes[i].metric);
		nm_ip4_config_take_route (config, route);
	}
	g_array_unref (routes_array);

	return config;
}

gboolean
nm_ip4_config_commit (NMIP4Config *config, int ifindex, int priority)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	int mtu = nm_ip4_config_get_mtu (config);
	int i;

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	/* Addresses */
	nm_platform_ip4_address_sync (ifindex, priv->addresses);

	/* Routes */
	{
		int count = nm_ip4_config_get_num_routes (config);
		NMIP4Route *config_route;
		GArray *routes = g_array_sized_new (FALSE, FALSE, sizeof (NMPlatformIP4Route), count);
		NMPlatformIP4Route route;

		for (i = 0; i < count; i++) {
			config_route = nm_ip4_config_get_route (config, i);
			memset (&route, 0, sizeof (route));
			route.network = nm_ip4_route_get_dest (config_route);
			route.plen = nm_ip4_route_get_prefix (config_route);
			route.gateway = nm_ip4_route_get_next_hop (config_route);
			route.metric = priority;

			/* Don't add the route if it's more specific than one of the subnets
			 * the device already has an IP address on.
			 */
			if (nm_ip4_config_destination_is_direct (config, route.network, route.plen))
				continue;

			/* Don't add the default route when and the connection
			 * is never supposed to be the default connection.
			 */
			if (nm_ip4_config_get_never_default (config) && route.network == 0)
				continue;

			g_array_append_val (routes, route);
		}

		nm_platform_ip4_route_sync (ifindex, routes);
		g_array_unref (routes);
	}

	/* MTU */
	if (mtu && mtu != nm_platform_link_get_mtu (ifindex))
		nm_platform_link_set_mtu (ifindex, mtu);

	return TRUE;
}

void
nm_ip4_config_merge_setting (NMIP4Config *config, NMSettingIP4Config *setting)
{
	guint naddresses, nroutes, nnameservers, nsearches;
	int i;

	if (!setting)
		return;

	naddresses = nm_setting_ip4_config_get_num_addresses (setting);
	nroutes = nm_setting_ip4_config_get_num_routes (setting);
	nnameservers = nm_setting_ip4_config_get_num_dns (setting);
	nsearches = nm_setting_ip4_config_get_num_dns_searches (setting);

	/* Gateway */
	if (nm_setting_ip4_config_get_never_default (setting))
		nm_ip4_config_set_never_default (config, TRUE);
	else if (nm_setting_ip4_config_get_ignore_auto_routes (setting))
		nm_ip4_config_set_never_default (config, FALSE);
	for (i = 0; i < naddresses; i++) {
		guint32 gateway = nm_ip4_address_get_gateway (nm_setting_ip4_config_get_address (setting, i));

		if (gateway) {
			nm_ip4_config_set_gateway (config, gateway);
			break;
		}
	}

	/* Addresses */
	for (i = 0; i < naddresses; i++) {
		NMIP4Address *s_addr = nm_setting_ip4_config_get_address (setting, i);
		NMPlatformIP4Address address;

		memset (&address, 0, sizeof (address));
		address.address = nm_ip4_address_get_address (s_addr);
		address.plen = nm_ip4_address_get_prefix (s_addr);
		address.lifetime = NM_PLATFORM_LIFETIME_PERMANENT;
		address.preferred = NM_PLATFORM_LIFETIME_PERMANENT;

		nm_ip4_config_add_address (config, &address);
	}

	/* Routes */
	if (nm_setting_ip4_config_get_ignore_auto_routes (setting))
		nm_ip4_config_reset_routes (config);
	for (i = 0; i < nroutes; i++)
		nm_ip4_config_add_route (config, nm_setting_ip4_config_get_route (setting, i));

	/* DNS */
	if (nm_setting_ip4_config_get_ignore_auto_dns (setting)) {
		nm_ip4_config_reset_nameservers (config);
		nm_ip4_config_reset_domains (config);
		nm_ip4_config_reset_searches (config);
	}
	for (i = 0; i < nnameservers; i++)
		nm_ip4_config_add_nameserver (config, nm_setting_ip4_config_get_dns (setting, i));
	for (i = 0; i < nsearches; i++)
		nm_ip4_config_add_search (config, nm_setting_ip4_config_get_dns_search (setting, i));
}

void
nm_ip4_config_update_setting (NMIP4Config *config, NMSettingIP4Config *setting)
{
	guint32 gateway;
	guint naddresses, nroutes, nnameservers, nsearches;
	const char *method = NULL;
	int i;

	if (!config)
		return;

	gateway = nm_ip4_config_get_gateway (config);
	naddresses = nm_ip4_config_get_num_addresses (config);
	nroutes = nm_ip4_config_get_num_routes (config);
	nnameservers = nm_ip4_config_get_num_nameservers (config);
	nsearches = nm_ip4_config_get_num_searches (config);

	/* Addresses */
	for (i = 0; i < naddresses; i++) {
		const NMPlatformIP4Address *address = nm_ip4_config_get_address (config, i);
		gs_unref_object NMIP4Address *s_addr = nm_ip4_address_new ();

		/* Detect dynamic address */
		if (address->lifetime != NM_PLATFORM_LIFETIME_PERMANENT) {
			method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;
			continue;
		}

		/* Static address found. */
		if (!method)
			method = NM_SETTING_IP4_CONFIG_METHOD_MANUAL;

		nm_ip4_address_set_address (s_addr, address->address);
		nm_ip4_address_set_prefix (s_addr, address->plen);
		/* For backwards compatibility, attach the gateway to an address if it's
		 * in the same subnet.
		 */
		if (same_prefix (address->address, gateway, address->plen))
			nm_ip4_address_set_gateway (s_addr, gateway);

		nm_setting_ip4_config_add_address (setting, s_addr);
	}
	if (!method)
		method = NM_SETTING_IP4_CONFIG_METHOD_DISABLED;
	g_object_set (setting, NM_SETTING_IP4_CONFIG_METHOD, method, NULL);

	/* Routes */
	for (i = 0; i < nroutes; i++) {
		NMIP4Route *route = nm_ip4_config_get_route (config, i);

		/* Ignore default route. */
		if (!nm_ip4_route_get_prefix (route))
			continue;

		nm_setting_ip4_config_add_route (setting, route);
	}

	/* DNS */
	for (i = 0; i < nnameservers; i++) {
		guint32 nameserver = nm_ip4_config_get_nameserver (config, i);

		nm_setting_ip4_config_add_dns (setting, nameserver);
	}
	for (i = 0; i < nsearches; i++) {
		const char *search = nm_ip4_config_get_search (config, i);

		nm_setting_ip4_config_add_dns_search (setting, search);
	}
}

/******************************************************************/

void
nm_ip4_config_merge (NMIP4Config *dst, NMIP4Config *src)
{
	guint32 i;

	g_return_if_fail (src != NULL);
	g_return_if_fail (dst != NULL);

	/* addresses */
	for (i = 0; i < nm_ip4_config_get_num_addresses (src); i++)
		nm_ip4_config_add_address (dst, nm_ip4_config_get_address (src, i));

	/* ptp address; only replace if src doesn't have one */
	if (!nm_ip4_config_get_ptp_address (dst))
		nm_ip4_config_set_ptp_address (dst, nm_ip4_config_get_ptp_address (src));

	/* nameservers */
	for (i = 0; i < nm_ip4_config_get_num_nameservers (src); i++)
		nm_ip4_config_add_nameserver (dst, nm_ip4_config_get_nameserver (src, i));

	/* default gateway */
	if (!nm_ip4_config_get_gateway (dst))
		nm_ip4_config_set_gateway (dst, nm_ip4_config_get_gateway (src));

	/* routes */
	for (i = 0; i < nm_ip4_config_get_num_routes (src); i++)
		nm_ip4_config_add_route (dst, nm_ip4_config_get_route (src, i));

	/* domains */
	for (i = 0; i < nm_ip4_config_get_num_domains (src); i++)
		nm_ip4_config_add_domain (dst, nm_ip4_config_get_domain (src, i));

	/* dns searches */
	for (i = 0; i < nm_ip4_config_get_num_searches (src); i++)
		nm_ip4_config_add_search (dst, nm_ip4_config_get_search (src, i));

	if (!nm_ip4_config_get_mss (dst))
		nm_ip4_config_set_mss (dst, nm_ip4_config_get_mss (src));

	/* NIS */
	for (i = 0; i < nm_ip4_config_get_num_nis_servers (src); i++)
		nm_ip4_config_add_nis_server (dst, nm_ip4_config_get_nis_server (src, i));

	if (nm_ip4_config_get_nis_domain (src))
		nm_ip4_config_set_nis_domain (dst, nm_ip4_config_get_nis_domain (src));

	/* WINS */
	for (i = 0; i < nm_ip4_config_get_num_wins (src); i++)
		nm_ip4_config_add_wins (dst, nm_ip4_config_get_wins (src, i));
}

/**
 * nm_ip4_config_subtract()
 * @dst: config from which to remove everything in @src
 * @src: config to remove from @dst
 *
 * Removes everything in @src from @dst.
 *
 */
void
nm_ip4_config_subtract (NMIP4Config *dst, NMIP4Config *src)
{
	guint32 i, j;

	g_return_if_fail (src != NULL);
	g_return_if_fail (dst != NULL);

	/* addresses */
	for (i = 0; i < nm_ip4_config_get_num_addresses (src); i++) {
		const NMPlatformIP4Address *src_addr = nm_ip4_config_get_address (src, i);

		for (j = 0; j < nm_ip4_config_get_num_addresses (dst); j++) {
			const NMPlatformIP4Address *dst_addr = nm_ip4_config_get_address (dst, j);

			if (src_addr->address == dst_addr->address &&
			    src_addr->plen == dst_addr->plen) {
				nm_ip4_config_del_address (dst, j);
				break;
			}
		}
	}

	/* ptp address */
	if (nm_ip4_config_get_ptp_address (src) == nm_ip4_config_get_ptp_address (dst))
		nm_ip4_config_set_ptp_address (dst, 0);

	/* nameservers */
	for (i = 0; i < nm_ip4_config_get_num_nameservers (src); i++) {
		guint32 src_ns = nm_ip4_config_get_nameserver (src, i);

		for (j = 0; j < nm_ip4_config_get_num_nameservers (dst); j++) {
			guint32 dst_ns = nm_ip4_config_get_nameserver (dst, j);

			if (dst_ns == src_ns) {
				nm_ip4_config_del_nameserver (dst, j);
				break;
			}
		}
	}

	/* default gateway */
	if (nm_ip4_config_get_gateway (src) == nm_ip4_config_get_gateway (dst))
		nm_ip4_config_set_gateway (dst, 0);

	/* routes */
	for (i = 0; i < nm_ip4_config_get_num_routes (src); i++) {
		NMIP4Route *src_route = nm_ip4_config_get_route (src, i);

		for (j = 0; j < nm_ip4_config_get_num_routes (dst); j++) {
			NMIP4Route *dst_route = nm_ip4_config_get_route (dst, j);

			if (nm_ip4_route_compare (src_route, dst_route)) {
				nm_ip4_config_del_route (dst, j);
				break;
			}
		}
	}

	/* domains */
	for (i = 0; i < nm_ip4_config_get_num_domains (src); i++) {
		const char *src_domain = nm_ip4_config_get_domain (src, i);

		for (j = 0; j < nm_ip4_config_get_num_domains (dst); j++) {
			const char *dst_domain = nm_ip4_config_get_domain (dst, j);

			if (g_strcmp0 (src_domain, dst_domain) == 0) {
				nm_ip4_config_del_domain (dst, j);
				break;
			}
		}
	}

	/* dns searches */
	for (i = 0; i < nm_ip4_config_get_num_searches (src); i++) {
		const char *src_search = nm_ip4_config_get_search (src, i);

		for (j = 0; j < nm_ip4_config_get_num_searches (dst); j++) {
			const char *dst_search = nm_ip4_config_get_search (dst, j);

			if (g_strcmp0 (src_search, dst_search) == 0) {
				nm_ip4_config_del_search (dst, j);
				break;
			}
		}
	}

	if (nm_ip4_config_get_mss (src) == nm_ip4_config_get_mss (dst))
		nm_ip4_config_set_mss (dst, 0);

	/* NIS */
	for (i = 0; i < nm_ip4_config_get_num_nis_servers (src); i++) {
		guint32 src_nis = nm_ip4_config_get_nis_server (src, i);

		for (j = 0; j < nm_ip4_config_get_num_nis_servers (dst); j++) {
			guint32 dst_nis = nm_ip4_config_get_nis_server (dst, j);

			if (dst_nis == src_nis) {
				nm_ip4_config_del_nis_server (dst, j);
				break;
			}
		}
	}

	if (g_strcmp0 (nm_ip4_config_get_nis_domain (src), nm_ip4_config_get_nis_domain (dst)) == 0)
		nm_ip4_config_set_nis_domain (dst, NULL);

	/* WINS */
	for (i = 0; i < nm_ip4_config_get_num_wins (src); i++) {
		guint32 src_wins = nm_ip4_config_get_wins (src, i);

		for (j = 0; j < nm_ip4_config_get_num_wins (dst); j++) {
			guint32 dst_wins = nm_ip4_config_get_wins (dst, j);

			if (dst_wins == src_wins) {
				nm_ip4_config_del_wins (dst, j);
				break;
			}
		}
	}
}

gboolean
nm_ip4_config_destination_is_direct (NMIP4Config *config, guint32 network, int plen)
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

	priv->never_default = never_default;
}

gboolean
nm_ip4_config_get_never_default (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->never_default;
}

void
nm_ip4_config_set_gateway (NMIP4Config *config, guint32 gateway)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	priv->gateway = gateway;
}

guint32
nm_ip4_config_get_gateway (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->gateway;
}

/******************************************************************/

void
nm_ip4_config_reset_addresses (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_array_set_size (priv->addresses, 0);
}

static gboolean
addresses_are_duplicate (const NMPlatformIP4Address *a, const NMPlatformIP4Address *b)
{
	return a->address == b->address;
}

void
nm_ip4_config_add_address (NMIP4Config *config, const NMPlatformIP4Address *new)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	int i;

	g_return_if_fail (new != NULL);

	for (i = 0; i < priv->addresses->len; i++ ) {
		NMPlatformIP4Address *item = &g_array_index (priv->addresses, NMPlatformIP4Address, i);

		if (addresses_are_duplicate (item, new)) {
			memcpy (item, new, sizeof (*item));
			return;
		}
	}

	g_array_append_val (priv->addresses, *new);
}

void
nm_ip4_config_del_address (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->addresses->len);

	g_array_remove_index (priv->addresses, i);
}

guint
nm_ip4_config_get_num_addresses (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->addresses->len;
}

const NMPlatformIP4Address *
nm_ip4_config_get_address (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return &g_array_index (priv->addresses, NMPlatformIP4Address, i);
}

/******************************************************************/

void
nm_ip4_config_reset_routes (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip4_route_unref);
	priv->routes = NULL;
}

static gboolean
routes_are_duplicate (NMIP4Route *a, NMIP4Route *b)
{
	if (nm_ip4_route_get_dest (a) != nm_ip4_route_get_dest (b))
		return FALSE;
	if (nm_ip4_route_get_prefix (a) != nm_ip4_route_get_prefix (b))
		return FALSE;

	return TRUE;
}

void
nm_ip4_config_add_route (NMIP4Config *config, NMIP4Route *new)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	GSList *iter;

	g_return_if_fail (new != NULL);

	for (iter = priv->routes; iter; iter = g_slist_next (iter)) {
		NMIP4Route *item = (NMIP4Route *) iter->data;

		if (routes_are_duplicate (item, new)) {
			nm_ip4_route_unref (item);
			iter->data = nm_ip4_route_dup (new);
			return;
		}
	}

	priv->routes = g_slist_append (priv->routes, nm_ip4_route_dup (new));
}

void
nm_ip4_config_take_route (NMIP4Config *config, NMIP4Route *route)
{
	g_return_if_fail (route != NULL);

	nm_ip4_config_add_route (config, route);
	nm_ip4_route_unref (route);
}

void
nm_ip4_config_del_route (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	GSList *iter, *last = priv->routes;
	guint n;

	if (i == 0) {
		last = priv->routes;
		priv->routes = last->next;
		last->next = NULL;
		g_slist_free_full (last, (GDestroyNotify) nm_ip4_route_unref);
	} else {
		for (iter = priv->routes->next, n = 1, last = NULL; iter; iter = iter->next, n++) {
			if (n == i) {
				last->next = iter->next;
				iter->next = NULL;
				g_slist_free_full (iter, (GDestroyNotify) nm_ip4_route_unref);
				break;
			}
			last = iter;
		}
	}
}

guint
nm_ip4_config_get_num_routes (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return g_slist_length (priv->routes);
}

NMIP4Route *
nm_ip4_config_get_route (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return (NMIP4Route *) g_slist_nth_data (priv->routes, i);
}

/******************************************************************/

void
nm_ip4_config_reset_nameservers (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_array_set_size (priv->nameservers, 0);
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
}

void
nm_ip4_config_del_nameserver (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->nameservers->len);

	g_array_remove_index (priv->nameservers, i);
}

guint32
nm_ip4_config_get_num_nameservers (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->nameservers->len;
}

guint32
nm_ip4_config_get_nameserver (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return g_array_index (priv->nameservers, guint32, i);
}

/******************************************************************/

void
nm_ip4_config_reset_domains (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_ptr_array_set_size (priv->domains, 0);
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
}

void
nm_ip4_config_del_domain (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->domains->len);

	g_ptr_array_remove_index (priv->domains, i);
}

guint32
nm_ip4_config_get_num_domains (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->domains->len;
}

const char *
nm_ip4_config_get_domain (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return g_ptr_array_index (priv->domains, i);
}

/******************************************************************/

void
nm_ip4_config_reset_searches (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_ptr_array_set_size (priv->searches, 0);
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
}

void
nm_ip4_config_del_search (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->searches->len);

	g_ptr_array_remove_index (priv->searches, i);
}

guint32
nm_ip4_config_get_num_searches (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->searches->len;
}

const char *
nm_ip4_config_get_search (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return g_ptr_array_index (priv->searches, i);
}

/******************************************************************/

void
nm_ip4_config_set_mss (NMIP4Config *config, guint32 mss)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	priv->mss = mss;
}

guint32
nm_ip4_config_get_mss (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->mss;
}

/******************************************************************/

void
nm_ip4_config_set_ptp_address (NMIP4Config *config, guint32 ptp_addr)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	priv->ptp_address = ptp_addr;
}

guint32
nm_ip4_config_get_ptp_address (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->ptp_address;
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
nm_ip4_config_get_num_nis_servers (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->nis->len;
}

guint32
nm_ip4_config_get_nis_server (NMIP4Config *config, guint i)
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
nm_ip4_config_get_nis_domain (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->nis_domain;
}

/******************************************************************/

void
nm_ip4_config_reset_wins (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_array_set_size (priv->wins, 0);
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
}

void
nm_ip4_config_del_wins (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	g_return_if_fail (i < priv->wins->len);

	g_array_remove_index (priv->wins, i);
}

guint32
nm_ip4_config_get_num_wins (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->wins->len;
}

guint32
nm_ip4_config_get_wins (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return g_array_index (priv->wins, guint32, i);
}

/******************************************************************/

void
nm_ip4_config_set_mtu (NMIP4Config *config, guint32 mtu)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	priv->mtu = mtu;
}

guint32
nm_ip4_config_get_mtu (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return priv->mtu;
}

/******************************************************************/

static inline void
hash_u32 (GChecksum *sum, guint32 n)
{
	g_checksum_update (sum, (const guint8 *) &n, sizeof (n));
}

void
nm_ip4_config_hash (NMIP4Config *config, GChecksum *sum, gboolean dns_only)
{
	guint32 i, n;
	const char *s;

	g_return_if_fail (config);
	g_return_if_fail (sum);

	if (!dns_only) {
		hash_u32 (sum, nm_ip4_config_get_gateway (config));

		for (i = 0; i < nm_ip4_config_get_num_addresses (config); i++) {
			const NMPlatformIP4Address *address = nm_ip4_config_get_address (config, i);
			hash_u32 (sum, address->address);
			hash_u32 (sum, address->plen);
		}

		for (i = 0; i < nm_ip4_config_get_num_routes (config); i++) {
			NMIP4Route *r = nm_ip4_config_get_route (config, i);

			hash_u32 (sum, nm_ip4_route_get_dest (r));
			hash_u32 (sum, nm_ip4_route_get_prefix (r));
			hash_u32 (sum, nm_ip4_route_get_next_hop (r));
			hash_u32 (sum, nm_ip4_route_get_metric (r));
		}

		n = nm_ip4_config_get_ptp_address (config);
		if (n)
			hash_u32 (sum, n);

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
}

gboolean
nm_ip4_config_equal (NMIP4Config *a, NMIP4Config *b)
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
	priv->nameservers = g_array_new (FALSE, FALSE, sizeof (guint32));
	priv->domains = g_ptr_array_new_with_free_func (g_free);
	priv->searches = g_ptr_array_new_with_free_func (g_free);
	priv->nis = g_array_new (FALSE, TRUE, sizeof (guint32));
	priv->wins = g_array_new (FALSE, TRUE, sizeof (guint32));
}

static void
finalize (GObject *object)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (object);

	g_array_unref (priv->addresses);
	g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip4_route_unref);
	g_array_unref (priv->nameservers);
	g_ptr_array_unref (priv->domains);
	g_ptr_array_unref (priv->searches);
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
	in_addr_t gateway = nm_ip4_config_get_gateway (config);

	switch (prop_id) {
	case PROP_ADDRESSES:
		{
			GPtrArray *addresses = g_ptr_array_new ();
			int naddr = nm_ip4_config_get_num_addresses (config);
			int i;

			for (i = 0; i < naddr; i++) {
				const NMPlatformIP4Address *address = nm_ip4_config_get_address (config, i);
				GArray *array = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 3);

				g_array_append_val (array, address->address);
				g_array_append_val (array, address->plen);
				g_array_append_val (array, gateway);

				g_ptr_array_add (addresses, array);
			}

			g_value_take_boxed (value, addresses);
		}
		break;
	case PROP_ROUTES:
		nm_utils_ip4_routes_to_gvalue (priv->routes, value);
		break;
	case PROP_NAMESERVERS:
		g_value_set_boxed (value, priv->nameservers);
		break;
	case PROP_DOMAINS:
		g_value_set_boxed (value, priv->domains);
		break;
	case PROP_WINS_SERVERS:
		g_value_set_boxed (value, priv->wins);
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

	g_type_class_add_private (config_class, sizeof (NMIP4ConfigPrivate));

	object_class->get_property = get_property;
	object_class->finalize = finalize;

	g_object_class_install_property
		(object_class, PROP_ADDRESSES,
		 g_param_spec_boxed (NM_IP4_CONFIG_ADDRESSES,
		                     "Addresses",
		                     "IP4 addresses",
		                     DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT,
		                     G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_ROUTES,
		 g_param_spec_boxed (NM_IP4_CONFIG_ROUTES,
		                     "Routes",
		                     "Routes",
		                     DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT,
		                     G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_NAMESERVERS,
		 g_param_spec_boxed (NM_IP4_CONFIG_NAMESERVERS,
		                     "Nameservers",
		                     "DNS list",
		                     DBUS_TYPE_G_UINT_ARRAY,
		                     G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_DOMAINS,
		 g_param_spec_boxed (NM_IP4_CONFIG_DOMAINS,
		                     "Domains",
		                     "Domains",
		                     DBUS_TYPE_G_ARRAY_OF_STRING,
		                     G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_WINS_SERVERS,
		 g_param_spec_boxed (NM_IP4_CONFIG_WINS_SERVERS,
		                     "WinsServers",
		                     "WINS server list",
		                     DBUS_TYPE_G_UINT_ARRAY,
		                     G_PARAM_READABLE));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (config_class), &dbus_glib_nm_ip4_config_object_info);
}
