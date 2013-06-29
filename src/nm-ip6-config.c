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

#include <string.h>

#include "nm-ip6-config.h"

#include "nm-glib-compat.h"
#include "gsystem-local-alloc.h"
#include "nm-platform.h"
#include "nm-utils.h"
#include "nm-dbus-manager.h"
#include "nm-dbus-glib-types.h"
#include "nm-ip6-config-glue.h"

G_DEFINE_TYPE (NMIP6Config, nm_ip6_config, G_TYPE_OBJECT)

#define NM_IP6_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IP6_CONFIG, NMIP6ConfigPrivate))

typedef struct {
	char *path;

	gboolean never_default;
	struct in6_addr gateway;
	GArray *addresses;
	GSList *routes;
	GArray *nameservers;
	GPtrArray *domains;
	GPtrArray *searches;
	guint32 mss;
	struct in6_addr ptp_address;
} NMIP6ConfigPrivate;


enum {
	PROP_0,
	PROP_ADDRESSES,
	PROP_NAMESERVERS,
	PROP_DOMAINS,
	PROP_ROUTES,

	LAST_PROP
};


NMIP6Config *
nm_ip6_config_new (void)
{
	return (NMIP6Config *) g_object_new (NM_TYPE_IP6_CONFIG, NULL);
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
nm_ip6_config_get_dbus_path (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return priv->path;
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

NMIP6Config *
nm_ip6_config_capture (int ifindex)
{
	NMIP6Config *config = nm_ip6_config_new ();
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	GArray *routes_array;
	NMPlatformIP6Route *routes;
	NMIP6Route *route;
	int i;

	g_array_unref (priv->addresses);
	priv->addresses = nm_platform_ip6_address_get_all (ifindex);

	if (!priv->addresses->len) {
		g_object_unref (config);
		return NULL;
	}

	routes_array = nm_platform_ip6_route_get_all (ifindex);
	routes = (NMPlatformIP6Route *)routes_array->data;
	for (i = 0; i < routes_array->len; i++) {
		/* Default route ignored; it's handled internally by NM and not
		* tracked in the device's IP config.
		*/
		if (routes[i].plen == 0)
			continue;

		route = nm_ip6_route_new ();
		nm_ip6_route_set_dest (route, &routes[i].network);
		nm_ip6_route_set_prefix (route, routes[i].plen);
		nm_ip6_route_set_next_hop (route, &routes[i].gateway);
		nm_ip6_route_set_metric (route, routes[i].metric);
		nm_ip6_config_take_route (config, route);
	}
	g_array_unref (routes_array);

	return config;
}

gboolean
nm_ip6_config_commit (NMIP6Config *config, int ifindex, int priority)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	int i;

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	/* Addresses */
	nm_platform_ip6_address_sync (ifindex, priv->addresses);

	/* Routes */
	{
		int count = nm_ip6_config_get_num_routes (config);
		NMIP6Route *config_route;
		GArray *routes = g_array_sized_new (FALSE, FALSE, sizeof (NMPlatformIP6Route), count);
		NMPlatformIP6Route route;

		for (i = 0; i < count; i++) {
			config_route = nm_ip6_config_get_route (config, i);
			memset (&route, 0, sizeof (route));
			route.network = *nm_ip6_route_get_dest (config_route);
			route.plen = nm_ip6_route_get_prefix (config_route);
			route.gateway = *nm_ip6_route_get_next_hop (config_route);
			route.metric = priority;

			/* Don't add the route if it's more specific than one of the subnets
			 * the device already has an IP address on.
			 */
			if (nm_ip6_config_destination_is_direct (config, &route.network, route.plen))
				continue;

			/* Don't add the default route when and the connection
			 * is never supposed to be the default connection.
			 */
			if (nm_ip6_config_get_never_default (config) && IN6_IS_ADDR_UNSPECIFIED (&route.network))
				continue;

			g_array_append_val (routes, route);
		}

		nm_platform_ip6_route_sync (ifindex, routes);
		g_array_unref (routes);
	}

	return TRUE;
}

static inline gboolean
ip6_addresses_equal (const struct in6_addr *a, const struct in6_addr *b)
{
	return memcmp (a, b, sizeof (struct in6_addr)) == 0;
}

void
nm_ip6_config_merge_setting (NMIP6Config *config, NMSettingIP6Config *setting)
{
	guint naddresses, nroutes, nnameservers, nsearches;
	int i;

	if (!setting)
		return;

	naddresses = nm_setting_ip6_config_get_num_addresses (setting);
	nroutes = nm_setting_ip6_config_get_num_routes (setting);
	nnameservers = nm_setting_ip6_config_get_num_dns (setting);
	nsearches = nm_setting_ip6_config_get_num_dns_searches (setting);

	/* Gateway */
	if (nm_setting_ip6_config_get_never_default (setting))
		nm_ip6_config_set_never_default (config, TRUE);
	else if (nm_setting_ip6_config_get_ignore_auto_routes (setting))
		nm_ip6_config_set_never_default (config, FALSE);
	for (i = 0; i < naddresses; i++) {
		const struct in6_addr *gateway = nm_ip6_address_get_gateway (nm_setting_ip6_config_get_address (setting, i));

		if (gateway && !IN6_IS_ADDR_UNSPECIFIED (gateway)) {
			nm_ip6_config_set_gateway (config, gateway);
			break;
		}
	}

	/* Addresses */
	for (i = 0; i < naddresses; i++) {
		NMIP6Address *s_addr = nm_setting_ip6_config_get_address (setting, i);
		NMPlatformIP6Address address;

		memset (&address, 0, sizeof (address));
		address.address = *nm_ip6_address_get_address (s_addr);
		address.plen = nm_ip6_address_get_prefix (s_addr);

		nm_ip6_config_add_address (config, &address);
	}

	/* Routes */
	if (nm_setting_ip6_config_get_ignore_auto_routes (setting))
		nm_ip6_config_reset_routes (config);
	for (i = 0; i < nroutes; i++)
		nm_ip6_config_add_route (config, nm_setting_ip6_config_get_route (setting, i));

	/* DNS */
	if (nm_setting_ip6_config_get_ignore_auto_dns (setting)) {
		nm_ip6_config_reset_nameservers (config);
		nm_ip6_config_reset_domains (config);
		nm_ip6_config_reset_searches (config);
	}
	for (i = 0; i < nnameservers; i++)
		nm_ip6_config_add_nameserver (config, nm_setting_ip6_config_get_dns (setting, i));
	for (i = 0; i < nsearches; i++)
		nm_ip6_config_add_search (config, nm_setting_ip6_config_get_dns_search (setting, i));
}

/******************************************************************/

void
nm_ip6_config_merge (NMIP6Config *dst, NMIP6Config *src)
{
	guint32 i;

	g_return_if_fail (src != NULL);
	g_return_if_fail (dst != NULL);

	/* addresses */
	for (i = 0; i < nm_ip6_config_get_num_addresses (src); i++)
		nm_ip6_config_add_address (dst, nm_ip6_config_get_address (src, i));

	/* ptp address; only replace if src doesn't have one */
	if (!nm_ip6_config_get_ptp_address (dst))
		nm_ip6_config_set_ptp_address (dst, nm_ip6_config_get_ptp_address (src));

	/* nameservers */
	for (i = 0; i < nm_ip6_config_get_num_nameservers (src); i++)
		nm_ip6_config_add_nameserver (dst, nm_ip6_config_get_nameserver (src, i));

	/* default gateway */
	if (!nm_ip6_config_get_gateway (dst))
		nm_ip6_config_set_gateway (dst, nm_ip6_config_get_gateway (src));

	/* routes */
	for (i = 0; i < nm_ip6_config_get_num_routes (src); i++)
		nm_ip6_config_add_route (dst, nm_ip6_config_get_route (src, i));

	/* domains */
	for (i = 0; i < nm_ip6_config_get_num_domains (src); i++)
		nm_ip6_config_add_domain (dst, nm_ip6_config_get_domain (src, i));

	/* dns searches */
	for (i = 0; i < nm_ip6_config_get_num_searches (src); i++)
		nm_ip6_config_add_search (dst, nm_ip6_config_get_search (src, i));

	if (!nm_ip6_config_get_mss (dst))
		nm_ip6_config_set_mss (dst, nm_ip6_config_get_mss (src));
}

gboolean
nm_ip6_config_destination_is_direct (NMIP6Config *config, const struct in6_addr *network, int plen)
{
	int num = nm_ip6_config_get_num_addresses (config);
	int i;

	for (i = 0; i < num; i++) {
		NMPlatformIP6Address *item = nm_ip6_config_get_address (config, i);

		if (item->plen <= plen && same_prefix (&item->address, network, item->plen))
			return TRUE;
	}

	return FALSE;
}

/******************************************************************/

void
nm_ip6_config_set_never_default (NMIP6Config *config, gboolean never_default)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	priv->never_default = never_default;
}

gboolean
nm_ip6_config_get_never_default (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return priv->never_default;
}

void
nm_ip6_config_set_gateway (NMIP6Config *config, const struct in6_addr *gateway)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	if (gateway)
		memcpy (&priv->gateway, gateway, sizeof (priv->gateway));
	else
		memset (&priv->gateway, 0, sizeof (priv->gateway));
}

const struct in6_addr *
nm_ip6_config_get_gateway (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return IN6_IS_ADDR_UNSPECIFIED (&priv->gateway) ? NULL : &priv->gateway;
}

/******************************************************************/

void
nm_ip6_config_reset_addresses (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	g_array_set_size (priv->nameservers, 0);
}

static gboolean
addresses_are_duplicate (const NMPlatformIP6Address *a, const NMPlatformIP6Address *b)
{
	return IN6_ARE_ADDR_EQUAL (&a->address, &b->address);
}

void
nm_ip6_config_add_address (NMIP6Config *config, const NMPlatformIP6Address *new)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	int i;

	for (i = 0; i < priv->addresses->len; i++ ) {
		NMPlatformIP6Address *item = &g_array_index (priv->addresses, NMPlatformIP6Address, i);

		if (addresses_are_duplicate (item, new)) {
			memcpy (item, new, sizeof (*item));
			return;
		}
	}

	g_array_append_val (priv->addresses, *new);
}

guint
nm_ip6_config_get_num_addresses (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return priv->addresses->len;
}

NMPlatformIP6Address *
nm_ip6_config_get_address (NMIP6Config *config, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return &g_array_index (priv->addresses, NMPlatformIP6Address, i);
}

/******************************************************************/

void
nm_ip6_config_reset_routes (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip6_route_unref);
	priv->routes = NULL;
}

static gboolean
routes_are_duplicate (NMIP6Route *a, NMIP6Route *b)
{
	if (nm_ip6_route_get_dest (a) != nm_ip6_route_get_dest (b))
		return FALSE;
	if (nm_ip6_route_get_prefix (a) != nm_ip6_route_get_prefix (b))
		return FALSE;

	return TRUE;
}

void
nm_ip6_config_add_route (NMIP6Config *config, NMIP6Route *new)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	GSList *iter;

	for (iter = priv->routes; iter; iter = g_slist_next (iter)) {
		NMIP6Route *item = (NMIP6Route *) iter->data;

		if (routes_are_duplicate (item, new)) {
			nm_ip6_route_unref (item);
			iter->data = nm_ip6_route_dup (new);
			return;
		}
	}

	priv->routes = g_slist_append (priv->routes, nm_ip6_route_dup (new));
}

void
nm_ip6_config_take_route (NMIP6Config *config, NMIP6Route *route)
{
	nm_ip6_config_add_route (config, route);
	nm_ip6_route_unref (route);
}

guint
nm_ip6_config_get_num_routes (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return g_slist_length (priv->routes);
}

NMIP6Route *
nm_ip6_config_get_route (NMIP6Config *config, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return (NMIP6Route *) g_slist_nth_data (priv->routes, i);
}

/******************************************************************/

void
nm_ip6_config_reset_nameservers (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	g_array_set_size (priv->nameservers, 0);
}

void
nm_ip6_config_add_nameserver (NMIP6Config *config, const struct in6_addr *new)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	int i;

	for (i = 0; i < priv->nameservers->len; i++)
		if (IN6_ARE_ADDR_EQUAL (new, &g_array_index (priv->nameservers, struct in6_addr, i)))
			return;

	g_array_append_val (priv->nameservers, *new);
}

guint32
nm_ip6_config_get_num_nameservers (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return priv->nameservers->len;
}

const struct in6_addr *
nm_ip6_config_get_nameserver (NMIP6Config *config, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return &g_array_index (priv->nameservers, struct in6_addr, i);
}

/******************************************************************/

void
nm_ip6_config_reset_domains (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	g_ptr_array_set_size (priv->domains, 0);
}

void
nm_ip6_config_add_domain (NMIP6Config *config, const char *domain)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	int i;

	for (i = 0; i < priv->domains->len; i++)
		if (!g_strcmp0 (g_ptr_array_index (priv->domains, i), domain))
			return;

	g_ptr_array_add (priv->domains, g_strdup (domain));
}

guint32
nm_ip6_config_get_num_domains (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return priv->domains->len;
}

const char *
nm_ip6_config_get_domain (NMIP6Config *config, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return g_ptr_array_index (priv->domains, i);
}

/******************************************************************/

void
nm_ip6_config_reset_searches (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	g_ptr_array_set_size (priv->searches, 0);
}

void
nm_ip6_config_add_search (NMIP6Config *config, const char *new)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	int i;

	g_return_if_fail (new && strlen (new));

	for (i = 0; i < priv->searches->len; i++)
		if (!g_strcmp0 (g_ptr_array_index (priv->searches, i), new))
			return;

	g_ptr_array_add (priv->searches, g_strdup (new));
}

guint32
nm_ip6_config_get_num_searches (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return priv->searches->len;
}

const char *
nm_ip6_config_get_search (NMIP6Config *config, guint i)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return g_ptr_array_index (priv->searches, i);
}

/******************************************************************/

void
nm_ip6_config_set_mss (NMIP6Config *config, guint32 mss)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	priv->mss = mss;
}

guint32
nm_ip6_config_get_mss (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return priv->mss;
}

/******************************************************************/

void
nm_ip6_config_set_ptp_address (NMIP6Config *config, const struct in6_addr *ptp_address)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	priv->ptp_address = *ptp_address;
}

const struct in6_addr *
nm_ip6_config_get_ptp_address (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	return &priv->ptp_address;
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
nm_ip6_config_hash (NMIP6Config *config, GChecksum *sum, gboolean dns_only)
{
	guint32 i;
	const struct in6_addr *in6a;
	const char *s;

	g_return_if_fail (config);
	g_return_if_fail (sum);

	if (dns_only == FALSE) {
		hash_in6addr (sum, nm_ip6_config_get_gateway (config));

		for (i = 0; i < nm_ip6_config_get_num_addresses (config); i++) {
			NMPlatformIP6Address *address = nm_ip6_config_get_address (config, i);

			hash_in6addr (sum, &address->address);
			hash_u32 (sum, address->plen);
		}

		for (i = 0; i < nm_ip6_config_get_num_routes (config); i++) {
			NMIP6Route *r = nm_ip6_config_get_route (config, i);

			hash_in6addr (sum, nm_ip6_route_get_dest (r));
			hash_u32 (sum, nm_ip6_route_get_prefix (r));
			hash_in6addr (sum, nm_ip6_route_get_next_hop (r));
			hash_u32 (sum, nm_ip6_route_get_metric (r));
		}

		in6a = nm_ip6_config_get_ptp_address (config);
		if (in6a)
			hash_in6addr (sum, in6a);
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
}

gboolean
nm_ip6_config_equal (NMIP6Config *a, NMIP6Config *b)
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
	priv->nameservers = g_array_new (FALSE, TRUE, sizeof (struct in6_addr));
	priv->domains = g_ptr_array_new_with_free_func (g_free);
	priv->searches = g_ptr_array_new_with_free_func (g_free);
}

static void
finalize (GObject *object)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (object);

	g_array_unref (priv->addresses);
	g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip6_route_unref);
	g_array_unref (priv->nameservers);
	g_ptr_array_unref (priv->domains);
	g_ptr_array_unref (priv->searches);

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
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMIP6Config *config = NM_IP6_CONFIG (object);
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_ADDRESSES:
		{
			GPtrArray *addresses = g_ptr_array_new ();
			const struct in6_addr *gateway = nm_ip6_config_get_gateway (config);
			int naddr = nm_ip6_config_get_num_addresses (config);
			int i;

			for (i = 0; i < naddr; i++) {
				NMPlatformIP6Address *address = nm_ip6_config_get_address (config, i);

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
				g_byte_array_append (ba, (guint8 *) gateway, 16);
				g_value_take_boxed (&element, ba);
				g_value_array_append (array, &element);
				g_value_unset (&element);

				g_ptr_array_add (addresses, array);
			}

			g_value_take_boxed (value, addresses);
		}
		break;
	case PROP_NAMESERVERS:
		nameservers_to_gvalue (priv->nameservers, value);
		break;
	case PROP_DOMAINS:
		g_value_set_boxed (value, priv->domains);
		break;
	case PROP_ROUTES:
		nm_utils_ip6_routes_to_gvalue (priv->routes, value);
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
	object_class->finalize = finalize;

	/* properties */
	g_object_class_install_property (object_class, PROP_ADDRESSES,
		g_param_spec_boxed (NM_IP6_CONFIG_ADDRESSES,
		                    "Addresses",
		                    "IP6 addresses",
		                    DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS,
		                    G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_NAMESERVERS,
		g_param_spec_boxed (NM_IP6_CONFIG_NAMESERVERS,
		                    "Nameservers",
		                    "DNS list",
		                    DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UCHAR,
		                    G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_DOMAINS,
		g_param_spec_boxed (NM_IP6_CONFIG_DOMAINS,
		                    "Domains",
		                    "Domains",
		                    DBUS_TYPE_G_ARRAY_OF_STRING,
		                    G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_ROUTES,
		g_param_spec_boxed (NM_IP6_CONFIG_ROUTES,
		                    "Routes",
		                    "Routes",
		                    DBUS_TYPE_G_ARRAY_OF_IP6_ROUTE,
		                    G_PARAM_READABLE));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (config_class),
									 &dbus_glib_nm_ip6_config_object_info);
}
