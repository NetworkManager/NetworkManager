/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-platform-fake.c - Fake platform interaction code for testing NetworkManager
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
 * Copyright (C) 2012–2013 Red Hat, Inc.
 */

#include <errno.h>
#include <unistd.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

#include "nm-fake-platform.h"
#include "nm-logging.h"

#define debug(format, ...) nm_log_dbg (LOGD_PLATFORM, format, __VA_ARGS__)

typedef struct {
	GArray *links;
	GArray *ip4_addresses;
	GArray *ip6_addresses;
	GArray *ip4_routes;
	GArray *ip6_routes;
} NMFakePlatformPrivate;

#define NM_FAKE_PLATFORM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_FAKE_PLATFORM, NMFakePlatformPrivate))

G_DEFINE_TYPE (NMFakePlatform, nm_fake_platform, NM_TYPE_PLATFORM)

/******************************************************************/

void
nm_fake_platform_setup (void)
{
	nm_platform_setup (NM_TYPE_FAKE_PLATFORM);
}

/******************************************************************/

static void
link_init (NMPlatformLink *device, int ifindex, int type, const char *name)
{
	g_assert (!name || strlen (name) < sizeof(device->name));

	memset (device, 0, sizeof (*device));

	device->ifindex = name ? ifindex : 0;
	device->type = type;
	if (name)
		strcpy (device->name, name);
	switch (device->type) {
	case NM_LINK_TYPE_DUMMY:
		device->arp = FALSE;
		break;
	default:
		device->arp = TRUE;
	}
}

static NMPlatformLink *
link_get (NMPlatform *platform, int ifindex)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	NMPlatformLink *device;

	if (ifindex >= priv->links->len)
		goto not_found;
	device = &g_array_index (priv->links, NMPlatformLink, ifindex);
	if (!device->ifindex)
		goto not_found;

	return device;
not_found:
	debug ("link not found: %d", ifindex);
	platform->error = NM_PLATFORM_ERROR_NOT_FOUND;
	return NULL;
}

static GArray *
link_get_all (NMPlatform *platform)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	GArray *links = g_array_sized_new (TRUE, TRUE, sizeof (NMPlatformLink), priv->links->len);
	int i;

	for (i = 0; i < priv->links->len; i++)
		if (g_array_index (priv->links, NMPlatformLink, i).ifindex)
			g_array_append_val (links, g_array_index (priv->links, NMPlatformLink, i));

	return links;
}

static gboolean
link_add (NMPlatform *platform, const char *name, NMLinkType type)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	NMPlatformLink device;

	link_init (&device, priv->links->len, type, name);

	g_array_append_val (priv->links, device);

	if (device.ifindex)
		g_signal_emit_by_name (platform, NM_PLATFORM_LINK_ADDED, &device);

	return TRUE;
}

static gboolean
link_delete (NMPlatform *platform, int ifindex)
{
	NMPlatformLink *device = link_get (platform, ifindex);
	NMPlatformLink deleted_device;

	if (!device)
		return FALSE;

	memcpy (&deleted_device, device, sizeof (deleted_device));
	memset (device, 0, sizeof (*device));

	g_signal_emit_by_name (platform, NM_PLATFORM_LINK_REMOVED, &deleted_device);

	return TRUE;
}

static int
link_get_ifindex (NMPlatform *platform, const char *name)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	int i;

	for (i = 0; i < priv->links->len; i++) {
		NMPlatformLink *device = &g_array_index (priv->links, NMPlatformLink, i);

		if (device && !g_strcmp0 (device->name, name))
			return device->ifindex;
	}

	return 0;
}

static const char *
link_get_name (NMPlatform *platform, int ifindex)
{
	NMPlatformLink *device = link_get (platform, ifindex);

	return device ? device->name : NULL;
}

static NMLinkType
link_get_type (NMPlatform *platform, int ifindex)
{
	NMPlatformLink *device = link_get (platform, ifindex);

	return device ? device->type : NM_LINK_TYPE_NONE;
}

static void
link_changed (NMPlatform *platform, NMPlatformLink *device)
{
	g_signal_emit_by_name (platform, "link-changed", device);
}

static gboolean
link_set_up (NMPlatform *platform, int ifindex)
{
	NMPlatformLink *device = link_get (platform, ifindex);

	if (!device)
		return FALSE;

	device->up = TRUE;
	switch (device->type) {
	case NM_LINK_TYPE_GENERIC:
	case NM_LINK_TYPE_DUMMY:
		device->connected = TRUE;
		break;
	default:
		device->connected = FALSE;
		g_error ("Unexpected device type: %d", device->type);
	}

	link_changed (platform, device);

	return TRUE;
}

static gboolean
link_set_down (NMPlatform *platform, int ifindex)
{
	NMPlatformLink *device = link_get (platform, ifindex);

	if (!device)
		return FALSE;

	device->up = FALSE;
	device->connected = FALSE;

	link_changed (platform, device);

	return TRUE;
}

static gboolean
link_set_arp (NMPlatform *platform, int ifindex)
{
	NMPlatformLink *device = link_get (platform, ifindex);

	if (!device)
		return FALSE;

	device->arp = TRUE;

	link_changed (platform, device);

	return TRUE;
}

static gboolean
link_set_noarp (NMPlatform *platform, int ifindex)
{
	NMPlatformLink *device = link_get (platform, ifindex);

	if (!device)
		return FALSE;

	device->arp = FALSE;

	link_changed (platform, device);

	return TRUE;
}

static gboolean
link_is_up (NMPlatform *platform, int ifindex)
{
	NMPlatformLink *device = link_get (platform, ifindex);

	return device ? device->up : FALSE;
}

static gboolean
link_is_connected (NMPlatform *platform, int ifindex)
{
	NMPlatformLink *device = link_get (platform, ifindex);

	return device ? device->connected : FALSE;
}

static gboolean
link_uses_arp (NMPlatform *platform, int ifindex)
{
	NMPlatformLink *device = link_get (platform, ifindex);

	return device ? device->arp : FALSE;
}

/******************************************************************/

static GArray *
ip4_address_get_all (NMPlatform *platform, int ifindex)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	GArray *addresses;
	NMPlatformIP4Address *address;
	int count = 0, i;

	/* Count addresses */
	for (i = 0; i < priv->ip4_addresses->len; i++) {
		address = &g_array_index (priv->ip4_addresses, NMPlatformIP4Address, i);
		if (address && address->ifindex == ifindex)
			count++;
	}

	addresses = g_array_sized_new (TRUE, TRUE, sizeof (NMPlatformIP4Address), count);

	/* Fill addresses */
	for (i = 0; i < priv->ip4_addresses->len; i++) {
		address = &g_array_index (priv->ip4_addresses, NMPlatformIP4Address, i);
		if (address && address->ifindex == ifindex)
			g_array_append_val (addresses, *address);
	}

	return addresses;
}

static GArray *
ip6_address_get_all (NMPlatform *platform, int ifindex)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	GArray *addresses;
	NMPlatformIP6Address *address;
	int count = 0, i;

	/* Count addresses */
	for (i = 0; i < priv->ip6_addresses->len; i++) {
		address = &g_array_index (priv->ip6_addresses, NMPlatformIP6Address, i);
		if (address && address->ifindex == ifindex)
			count++;
	}

	addresses = g_array_sized_new (TRUE, TRUE, sizeof (NMPlatformIP6Address), count);

	/* Fill addresses */
	count = 0;
	for (i = 0; i < priv->ip6_addresses->len; i++) {
		address = &g_array_index (priv->ip6_addresses, NMPlatformIP6Address, i);
		if (address && address->ifindex == ifindex)
			g_array_append_val (addresses, *address);
	}

	return addresses;
}

static gboolean
ip4_address_add (NMPlatform *platform, int ifindex, in_addr_t addr, int plen)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	NMPlatformIP4Address address;

	memset (&address, 0, sizeof (address));
	address.ifindex = ifindex;
	address.address = addr;
	address.plen = plen;

	g_array_append_val (priv->ip4_addresses, address);

	g_signal_emit_by_name (platform, NM_PLATFORM_IP4_ADDRESS_ADDED, &address);

	return TRUE;
}

static gboolean
ip6_address_add (NMPlatform *platform, int ifindex, struct in6_addr addr, int plen)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	NMPlatformIP6Address address;

	memset (&address, 0, sizeof (address));
	address.ifindex = ifindex;
	address.address = addr;
	address.plen = plen;

	g_array_append_val (priv->ip6_addresses, address);

	g_signal_emit_by_name (platform, NM_PLATFORM_IP6_ADDRESS_ADDED, &address);

	return TRUE;
}

static gboolean
ip4_address_delete (NMPlatform *platform, int ifindex, in_addr_t addr, int plen)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	int i;

	for (i = 0; i < priv->ip4_addresses->len; i++) {
		NMPlatformIP4Address *address = &g_array_index (priv->ip4_addresses, NMPlatformIP4Address, i);

		if (address->ifindex == ifindex && address->plen == plen && address->address == addr) {
			NMPlatformIP4Address deleted_address;

			memcpy (&deleted_address, address, sizeof (deleted_address));
			memset (address, 0, sizeof (*address));
			g_signal_emit_by_name (platform, NM_PLATFORM_IP4_ADDRESS_REMOVED, &deleted_address);
			return TRUE;
		}
	}

	g_assert_not_reached ();
}

static gboolean
ip6_address_delete (NMPlatform *platform, int ifindex, struct in6_addr addr, int plen)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	int i;

	for (i = 0; i < priv->ip6_addresses->len; i++) {
		NMPlatformIP6Address *address = &g_array_index (priv->ip6_addresses, NMPlatformIP6Address, i);

		if (address->ifindex == ifindex && address->plen == plen
				&& IN6_ARE_ADDR_EQUAL (&address->address, &addr)) {
			NMPlatformIP6Address deleted_address;

			memcpy (&deleted_address, address, sizeof (deleted_address));
			memset (address, 0, sizeof (*address));
			g_signal_emit_by_name (platform, NM_PLATFORM_IP6_ADDRESS_REMOVED, &deleted_address);
			return TRUE;
		}
	}

	g_assert_not_reached ();
}

static gboolean
ip4_address_exists (NMPlatform *platform, int ifindex, in_addr_t addr, int plen)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	int i;

	for (i = 0; i < priv->ip4_addresses->len; i++) {
		NMPlatformIP4Address *address = &g_array_index (priv->ip4_addresses, NMPlatformIP4Address, i);

		if (address->ifindex == ifindex && address->plen == plen && address->address == addr)
			return TRUE;
	}

	return FALSE;
}

static gboolean
ip6_address_exists (NMPlatform *platform, int ifindex, struct in6_addr addr, int plen)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	int i;

	for (i = 0; i < priv->ip6_addresses->len; i++) {
		NMPlatformIP6Address *address = &g_array_index (priv->ip6_addresses, NMPlatformIP6Address, i);

		if (address->ifindex == ifindex && address->plen == plen &&
				IN6_ARE_ADDR_EQUAL (&address->address, &addr))
			return TRUE;
	}

	return FALSE;
}

/******************************************************************/

static GArray *
ip4_route_get_all (NMPlatform *platform, int ifindex)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	GArray *routes;
	NMPlatformIP4Route *route;
	int count = 0, i;

	/* Count routes */
	for (i = 0; i < priv->ip4_routes->len; i++) {
		route = &g_array_index (priv->ip4_routes, NMPlatformIP4Route, i);
		if (route && route->ifindex == ifindex)
			count++;
	}

	routes = g_array_sized_new (TRUE, TRUE, sizeof (NMPlatformIP4Route), count);

	/* Fill routes */
	for (i = 0; i < priv->ip4_routes->len; i++) {
		route = &g_array_index (priv->ip4_routes, NMPlatformIP4Route, i);
		if (route && route->ifindex == ifindex)
			g_array_append_val (routes, *route);
	}

	return routes;
}

static GArray *
ip6_route_get_all (NMPlatform *platform, int ifindex)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	GArray *routes;
	NMPlatformIP6Route *route;
	int count = 0, i;

	/* Count routes */
	for (i = 0; i < priv->ip6_routes->len; i++) {
		route = &g_array_index (priv->ip6_routes, NMPlatformIP6Route, i);
		if (route && route->ifindex == ifindex)
			count++;
	}

	routes = g_array_sized_new (TRUE, TRUE, sizeof (NMPlatformIP6Route), count);

	/* Fill routes */
	for (i = 0; i < priv->ip6_routes->len; i++) {
		route = &g_array_index (priv->ip6_routes, NMPlatformIP6Route, i);
		if (route && route->ifindex == ifindex)
			g_array_append_val (routes, *route);
	}

	return routes;
}

static gboolean
ip4_route_add (NMPlatform *platform, int ifindex, in_addr_t network, int plen,
		in_addr_t gateway, int metric, int mss)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	NMPlatformIP4Route route;

	memset (&route, 0, sizeof (route));
	route.ifindex = ifindex;
	route.network = network;
	route.plen = plen;
	route.gateway = gateway;
	route.metric = metric;

	g_array_append_val (priv->ip4_routes, route);

	g_signal_emit_by_name (platform, NM_PLATFORM_IP4_ROUTE_ADDED, &route);

	return TRUE;
}

static gboolean
ip6_route_add (NMPlatform *platform, int ifindex, struct in6_addr network, int plen,
		struct in6_addr gateway, int metric, int mss)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	NMPlatformIP6Route route;

	memset (&route, 0, sizeof (route));
	route.ifindex = ifindex;
	route.network = network;
	route.plen = plen;
	route.gateway = gateway;
	route.metric = metric;

	g_array_append_val (priv->ip6_routes, route);

	g_signal_emit_by_name (platform, NM_PLATFORM_IP6_ROUTE_ADDED, &route);

	return TRUE;
}

static NMPlatformIP4Route *
ip4_route_get (NMPlatform *platform, int ifindex, in_addr_t network, int plen,
		in_addr_t gateway, int metric)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	int i;

	for (i = 0; i < priv->ip4_routes->len; i++) {
		NMPlatformIP4Route *route = &g_array_index (priv->ip4_routes, NMPlatformIP4Route, i);

		if (route->ifindex == ifindex
				&& route->network == network
				&& route->plen == plen
				&& route->gateway == gateway
				&& route->metric == metric)
			return route;
	}

	return NULL;
}

static NMPlatformIP6Route *
ip6_route_get (NMPlatform *platform, int ifindex, struct in6_addr network, int plen,
		struct in6_addr gateway, int metric)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	int i;

	for (i = 0; i < priv->ip6_routes->len; i++) {
		NMPlatformIP6Route *route = &g_array_index (priv->ip6_routes, NMPlatformIP6Route, i);

		if (route->ifindex == ifindex
				&& IN6_ARE_ADDR_EQUAL (&route->network, &network)
				&& route->plen == plen
				&& IN6_ARE_ADDR_EQUAL (&route->gateway, &gateway)
				&& route->metric == metric)
			return route;
	}

	return NULL;
}

static gboolean
ip4_route_delete (NMPlatform *platform, int ifindex, in_addr_t network, int plen,
		in_addr_t gateway, int metric)
{
	NMPlatformIP4Route *route = ip4_route_get (platform, ifindex, network, plen, gateway, metric);
	NMPlatformIP4Route deleted_route;

	g_assert (route);

	memcpy (&deleted_route, route, sizeof (deleted_route));
	memset (route, 0, sizeof (*route));
	g_signal_emit_by_name (platform, NM_PLATFORM_IP4_ROUTE_REMOVED, &deleted_route);

	return TRUE;
}

static gboolean
ip6_route_delete (NMPlatform *platform, int ifindex, struct in6_addr network, int plen,
		struct in6_addr gateway, int metric)
{
	NMPlatformIP6Route *route = ip6_route_get (platform, ifindex, network, plen, gateway, metric);
	NMPlatformIP6Route deleted_route;

	g_assert (route);

	memcpy (&deleted_route, route, sizeof (deleted_route));
	memset (route, 0, sizeof (*route));
	g_signal_emit_by_name (platform, NM_PLATFORM_IP6_ROUTE_REMOVED, &deleted_route);

	return TRUE;
}

static gboolean
ip4_route_exists (NMPlatform *platform, int ifindex, in_addr_t network, int plen,
		in_addr_t gateway, int metric)
{
	return !!ip4_route_get (platform, ifindex, network, plen, gateway, metric);
}

static gboolean
ip6_route_exists (NMPlatform *platform, int ifindex, struct in6_addr network, int plen,
		struct in6_addr gateway, int metric)
{
	return !!ip6_route_get (platform, ifindex, network, plen, gateway, metric);
}

/******************************************************************/

static void
nm_fake_platform_init (NMFakePlatform *fake_platform)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (fake_platform);

	priv->links = g_array_new (TRUE, TRUE, sizeof (NMPlatformLink));
	priv->ip4_addresses = g_array_new (TRUE, TRUE, sizeof (NMPlatformIP4Address));
	priv->ip6_addresses = g_array_new (TRUE, TRUE, sizeof (NMPlatformIP6Address));
	priv->ip4_routes = g_array_new (TRUE, TRUE, sizeof (NMPlatformIP4Route));
	priv->ip6_routes = g_array_new (TRUE, TRUE, sizeof (NMPlatformIP6Route));
}

static gboolean
setup (NMPlatform *platform)
{
	/* skip zero element */
	link_add (platform, NULL, NM_LINK_TYPE_NONE);

	/* add loopback interface */
	link_add (platform, "lo", NM_LINK_TYPE_LOOPBACK);

	/* add some ethernets */
	link_add (platform, "eth0", NM_LINK_TYPE_ETHERNET);
	link_add (platform, "eth1", NM_LINK_TYPE_ETHERNET);
	link_add (platform, "eth2", NM_LINK_TYPE_ETHERNET);

	return TRUE;
}

static void
nm_fake_platform_finalize (GObject *object)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (object);

	g_array_unref (priv->links);
	g_array_unref (priv->ip4_addresses);
	g_array_unref (priv->ip6_addresses);
	g_array_unref (priv->ip4_routes);
	g_array_unref (priv->ip6_routes);

	G_OBJECT_CLASS (nm_fake_platform_parent_class)->finalize (object);
}

static void
nm_fake_platform_class_init (NMFakePlatformClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMPlatformClass *platform_class = NM_PLATFORM_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMFakePlatformPrivate));

	/* virtual methods */
	object_class->finalize = nm_fake_platform_finalize;

	platform_class->setup = setup;

	platform_class->link_get_all = link_get_all;
	platform_class->link_add = link_add;
	platform_class->link_delete = link_delete;
	platform_class->link_get_ifindex = link_get_ifindex;
	platform_class->link_get_name = link_get_name;
	platform_class->link_get_type = link_get_type;

	platform_class->link_set_up = link_set_up;
	platform_class->link_set_down = link_set_down;
	platform_class->link_set_arp = link_set_arp;
	platform_class->link_set_noarp = link_set_noarp;
	platform_class->link_is_up = link_is_up;
	platform_class->link_is_connected = link_is_connected;
	platform_class->link_uses_arp = link_uses_arp;

	platform_class->ip4_address_get_all = ip4_address_get_all;
	platform_class->ip6_address_get_all = ip6_address_get_all;
	platform_class->ip4_address_add = ip4_address_add;
	platform_class->ip6_address_add = ip6_address_add;
	platform_class->ip4_address_delete = ip4_address_delete;
	platform_class->ip6_address_delete = ip6_address_delete;
	platform_class->ip4_address_exists = ip4_address_exists;
	platform_class->ip6_address_exists = ip6_address_exists;

	platform_class->ip4_route_get_all = ip4_route_get_all;
	platform_class->ip6_route_get_all = ip6_route_get_all;
	platform_class->ip4_route_add = ip4_route_add;
	platform_class->ip6_route_add = ip6_route_add;
	platform_class->ip4_route_delete = ip4_route_delete;
	platform_class->ip6_route_delete = ip6_route_delete;
	platform_class->ip4_route_exists = ip4_route_exists;
	platform_class->ip6_route_exists = ip6_route_exists;
}
