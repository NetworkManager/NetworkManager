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
	GSList *addresses;
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
	NMIP4Config *config;
	GArray *addrs_array, *routes_array;
	NMPlatformIP4Address *addrs;
	NMPlatformIP4Route *routes;
	NMIP4Address *addr;
	NMIP4Route *route;
	int i;

	addrs_array = nm_platform_ip4_address_get_all (ifindex);
	if (addrs_array->len == 0) {
		g_array_unref (addrs_array);
		return NULL;
	}

	config = nm_ip4_config_new ();

	addrs = (NMPlatformIP4Address *)addrs_array->data;
	for (i = 0; i < addrs_array->len; i++) {
		addr = nm_ip4_address_new ();
		nm_ip4_address_set_address (addr, addrs[i].address);
		nm_ip4_address_set_prefix (addr, addrs[i].plen);
		nm_ip4_config_take_address (config, addr);
	}
	g_array_unref (addrs_array);

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
	int mtu = nm_ip4_config_get_mtu (config);
	int i;

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	/* Addresses */
	{
		int count = nm_ip4_config_get_num_addresses (config);
		NMIP4Address *config_address;
		GArray *addresses = g_array_sized_new (FALSE, FALSE, sizeof (NMPlatformIP4Address), count);
		NMPlatformIP4Address address;

		for (i = 0; i < count; i++) {
			config_address = nm_ip4_config_get_address (config, i);
			memset (&address, 0, sizeof (address));
			address.address = nm_ip4_address_get_address (config_address);
			address.plen = nm_ip4_address_get_prefix (config_address);
			g_array_append_val (addresses, address);
		}

		nm_platform_ip4_address_sync (ifindex, addresses);
		g_array_unref (addresses);
	}

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
	for (i = 0; i < naddresses; i++)
		nm_ip4_config_add_address (config, nm_setting_ip4_config_get_address (setting, i));

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

/******************************************************************/

gboolean
nm_ip4_config_destination_is_direct (NMIP4Config *config, guint32 network, int plen)
{
	guint naddresses = nm_ip4_config_get_num_addresses (config);
	int i;

	for (i = 0; i < naddresses; i++) {
		NMIP4Address *item = nm_ip4_config_get_address (config, i);
		guint32 item_address = nm_ip4_address_get_address (item);
		int item_plen = nm_ip4_address_get_prefix (item);

		if (item_plen <= plen && same_prefix (item_address, network, item_plen));
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

	g_slist_free_full (priv->addresses, (GDestroyNotify) nm_ip4_address_unref);
	priv->addresses = NULL;
}

static gboolean
addresses_are_duplicate (NMIP4Address *a, NMIP4Address *b)
{
	if (nm_ip4_address_get_address (a) != nm_ip4_address_get_address (b))
		return FALSE;

	return TRUE;
}

void
nm_ip4_config_add_address (NMIP4Config *config, NMIP4Address *new)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	GSList *iter;

	for (iter = priv->addresses; iter; iter = g_slist_next (iter)) {
		NMIP4Address *item = (NMIP4Address *) iter->data;

		if (addresses_are_duplicate (item, new)) {
			nm_ip4_address_unref (item);
			iter->data = nm_ip4_address_dup (new);
			return;
		}
	}

	priv->addresses = g_slist_append (priv->addresses, nm_ip4_address_dup (new));
}

void
nm_ip4_config_take_address (NMIP4Config *config, NMIP4Address *address)
{
	nm_ip4_config_add_address (config, address);
	nm_ip4_address_unref (address);
}

guint
nm_ip4_config_get_num_addresses (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return g_slist_length (priv->addresses);
}

NMIP4Address *
nm_ip4_config_get_address (NMIP4Config *config, guint i)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	return (NMIP4Address *) g_slist_nth_data (priv->addresses, i);
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
	nm_ip4_config_add_route (config, route);
	nm_ip4_route_unref (route);
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

	for (i = 0; i < priv->nameservers->len; i++)
		if (new == g_array_index (priv->nameservers, guint32, i))
			return;

	g_array_append_val (priv->nameservers, new);
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

	for (i = 0; i < priv->domains->len; i++)
		if (!g_strcmp0 (g_ptr_array_index (priv->domains, i), domain))
			return;

	g_ptr_array_add (priv->domains, g_strdup (domain));
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

	g_return_if_fail (new && strlen (new));

	for (i = 0; i < priv->searches->len; i++)
		if (!g_strcmp0 (g_ptr_array_index (priv->searches, i), new))
			return;

	g_ptr_array_add (priv->searches, g_strdup (new));
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

	for (i = 0; i < priv->wins->len; i++)
		if (wins == g_array_index (priv->wins, guint32, i))
			return;

	g_array_append_val (priv->wins, wins);
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

static gboolean
addr_slist_compare (GSList *a, GSList *b)
{
	GSList *iter_a, *iter_b;
	gboolean found = FALSE;

	for (iter_a = a; iter_a; iter_a = g_slist_next (iter_a)) {
		NMIP4Address *addr_a = (NMIP4Address *) iter_a->data;

		for (iter_b = b, found = FALSE; iter_b; iter_b = g_slist_next (iter_b)) {
			NMIP4Address *addr_b = (NMIP4Address *) iter_b->data;

			if (nm_ip4_address_compare (addr_a, addr_b)) {
				found = TRUE;
				break;
			}
		}

		if (!found)
			return FALSE;
	}
	return TRUE;
}

static gboolean
route_slist_compare (GSList *a, GSList *b)
{
	GSList *iter_a, *iter_b;
	gboolean found = FALSE;

	for (iter_a = a; iter_a; iter_a = g_slist_next (iter_a)) {
		NMIP4Route *route_a = (NMIP4Route *) iter_a->data;

		for (iter_b = b, found = FALSE; iter_b; iter_b = g_slist_next (iter_b)) {
			NMIP4Route *route_b = (NMIP4Route *) iter_b->data;

			if (nm_ip4_route_compare (route_a, route_b)) {
				found = TRUE;
				break;
			}
		}

		if (!found)
			return FALSE;
	}
	return TRUE;
}

static gboolean
string_array_compare (GPtrArray *a, GPtrArray *b)
{
	int i, j;
	gboolean found = FALSE;

	for (i = 0; i < a->len; i++) {
		for (j = 0, found = FALSE; j < b->len; j++) {
			const char *item_a = g_ptr_array_index (a, i);
			const char *item_b = g_ptr_array_index (b, j);

			if ((!item_a && !item_b) || (item_a && item_b && !strcmp (item_a, item_b))) {
				found = TRUE;
				break;
			}
		}

		if (!found)
			return FALSE;
	}
	return TRUE;
}

static gboolean
addr_array_compare (GArray *a, GArray *b)
{
	int i, j;
	gboolean found = FALSE;

	for (i = 0; i < a->len; i++) {
		for (j = 0, found = FALSE; j < b->len; j++) {
			if (g_array_index (a, guint32, i) == g_array_index (b, guint32, j)) {
				found = TRUE;
				break;
			}
		}

		if (!found)
			return FALSE;
	}
	return TRUE;
}

NMIP4ConfigCompareFlags
nm_ip4_config_diff (NMIP4Config *a, NMIP4Config *b)
{
	NMIP4ConfigPrivate *a_priv;
	NMIP4ConfigPrivate *b_priv;
	NMIP4ConfigCompareFlags flags = NM_IP4_COMPARE_FLAG_NONE;

	if (!a && !b)
		return NM_IP4_COMPARE_FLAG_NONE;
	if (!a || !b)
		return NM_IP4_COMPARE_FLAG_ALL;

	a_priv = NM_IP4_CONFIG_GET_PRIVATE (a);
	b_priv = NM_IP4_CONFIG_GET_PRIVATE (b);

	if (   !addr_slist_compare (a_priv->addresses, b_priv->addresses)
	    || !addr_slist_compare (b_priv->addresses, a_priv->addresses))
		flags |= NM_IP4_COMPARE_FLAG_ADDRESSES;

	if (a_priv->ptp_address != b_priv->ptp_address)
		flags |= NM_IP4_COMPARE_FLAG_PTP_ADDRESS;

	if (   (a_priv->nameservers->len != b_priv->nameservers->len)
	    || !addr_array_compare (a_priv->nameservers, b_priv->nameservers)
	    || !addr_array_compare (b_priv->nameservers, a_priv->nameservers))
		flags |= NM_IP4_COMPARE_FLAG_NAMESERVERS;

	if (   (a_priv->wins->len != b_priv->wins->len)
	    || !addr_array_compare (a_priv->wins, b_priv->wins)
	    || !addr_array_compare (b_priv->wins, a_priv->wins))
		flags |= NM_IP4_COMPARE_FLAG_WINS_SERVERS;

	if (   (a_priv->nis->len != b_priv->nis->len)
	    || !addr_array_compare (a_priv->nis, b_priv->nis)
	    || !addr_array_compare (b_priv->nis, a_priv->nis))
		flags |= NM_IP4_COMPARE_FLAG_NIS_SERVERS;

	if (   (a_priv->nis_domain || b_priv->nis_domain)
		&& (g_strcmp0 (a_priv->nis_domain, b_priv->nis_domain) != 0))
		flags |= NM_IP4_COMPARE_FLAG_NIS_DOMAIN;

	if (   !route_slist_compare (a_priv->routes, b_priv->routes)
	    || !route_slist_compare (b_priv->routes, a_priv->routes))
		flags |= NM_IP4_COMPARE_FLAG_ROUTES;

	if (   (a_priv->domains->len != b_priv->domains->len)
	    || !string_array_compare (a_priv->domains, b_priv->domains)
	    || !string_array_compare (b_priv->domains, a_priv->domains))
		flags |= NM_IP4_COMPARE_FLAG_DOMAINS;

	if (   (a_priv->searches->len != b_priv->searches->len)
	    || !string_array_compare (a_priv->searches, b_priv->searches)
	    || !string_array_compare (b_priv->searches, a_priv->searches))
		flags |= NM_IP4_COMPARE_FLAG_SEARCHES;

	if (a_priv->mtu != b_priv->mtu)
		flags |= NM_IP4_COMPARE_FLAG_MTU;

	if (a_priv->mss != b_priv->mss)
		flags |= NM_IP4_COMPARE_FLAG_MSS;

	return flags;
}

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

	g_return_if_fail (config != NULL);
	g_return_if_fail (sum != NULL);

	if (dns_only == FALSE) {
		hash_u32 (sum, nm_ip4_config_get_gateway (config));

		for (i = 0; i < nm_ip4_config_get_num_addresses (config); i++) {
			NMIP4Address *a = nm_ip4_config_get_address (config, i);

			hash_u32 (sum, nm_ip4_address_get_address (a));
			hash_u32 (sum, nm_ip4_address_get_prefix (a));
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

/******************************************************************/

static void
nm_ip4_config_init (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

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

	g_slist_free_full (priv->addresses, (GDestroyNotify) nm_ip4_address_unref);
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
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_ADDRESSES:
		nm_utils_ip4_addresses_to_gvalue (priv->addresses, value);
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
