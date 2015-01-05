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
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include <string.h>

#include "config.h"

#include "nm-route-manager.h"
#include "nm-platform.h"
#include "nm-logging.h"

#include "NetworkManagerUtils.h"

typedef struct {
	GArray *ip4_routes;
	GArray *ip6_routes;
} NMRouteManagerPrivate;

#define NM_ROUTE_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_ROUTE_MANAGER, NMRouteManagerPrivate))

G_DEFINE_TYPE (NMRouteManager, nm_route_manager, G_TYPE_OBJECT)

static NMRouteManager *_instance;

static const NMPlatformIP4Route *
array_get_ip4_route (const GArray *routes, int ifindex, const NMPlatformIP4Route *route)
{
	guint len = routes ? routes->len : 0;
	guint i;

	for (i = 0; i < len; i++) {
		NMPlatformIP4Route *c = &g_array_index (routes, NMPlatformIP4Route, i);

		if (ifindex) {
			/* Looking for a specific route. */
			if (   c->ifindex != ifindex
		            || route->mss != c->mss
			    || route->gateway != c->gateway)
			continue;
		}

		if (route->network == c->network &&
		    route->plen == c->plen &&
		    route->metric == c->metric)
			return c;
	}

	return NULL;
}

static const NMPlatformIP6Route *
array_get_ip6_route (const GArray *routes, int ifindex, const NMPlatformIP6Route *route)
{
	guint len = routes ? routes->len : 0;
	guint i;

	for (i = 0; i < len; i++) {
		NMPlatformIP6Route *c = &g_array_index (routes, NMPlatformIP6Route, i);
		int route_metric = nm_utils_ip6_route_metric_normalize (route->metric);
		int c_metric = nm_utils_ip6_route_metric_normalize (c->metric);

		if (ifindex) {
			/* Looking for a specific route. */
			if (   c->ifindex != ifindex
		            || route->mss != c->mss
			    || !IN6_ARE_ADDR_EQUAL (&route->gateway, &c->gateway))
				continue;
		}

		if (IN6_ARE_ADDR_EQUAL (&route->network, &c->network) &&
		    route->plen == c->plen &&
		    route_metric == c_metric)
			return c;
	}

	return NULL;
}


/**
 * nm_route_manager_ip4_route_sync:
 * @ifindex: Interface index
 * @known_routes: List of routes
 *
 * A convenience function to synchronize routes for a specific interface
 * with the least possible disturbance. It simply removes routes that are
 * not listed and adds routes that are.
 * Default routes are ignored (both in @known_routes and those already
 * configured on the device).
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_route_manager_ip4_route_sync (NMRouteManager *self, int ifindex, const GArray *known_routes)
{
	NMRouteManagerPrivate *priv = NM_ROUTE_MANAGER_GET_PRIVATE (self);
	GArray *plat_routes, *routes = priv->ip4_routes;
	NMPlatformIP4Route route;
	const NMPlatformIP4Route *known_route;
	const NMPlatformIP4Route *existing;
	gboolean success;
	int i, i_type;

	/* Learn about routes that platform knows but we don't. */
	plat_routes = nm_platform_ip4_route_get_all (NM_PLATFORM_GET, 0, NM_PLATFORM_GET_ROUTE_MODE_NO_DEFAULT);
	for (i = 0; i < plat_routes->len; i++) {
		existing = &g_array_index (plat_routes, NMPlatformIP4Route, i);
		if (!array_get_ip4_route (routes, existing->ifindex, existing))
			g_array_append_val (routes, *existing);
	}

	/* Delete unknown routes */
	for (i = 0; i < routes->len;) {
		route = g_array_index (routes, NMPlatformIP4Route, i);

		if (route.ifindex == ifindex) {
			/* Our route. Keep it? */
			if (array_get_ip4_route (known_routes, route.ifindex, &route)) {
				i++;
				continue;
			}

			g_array_remove_index (routes, i);
		} else {
			i++;
		}

		existing = array_get_ip4_route (routes, 0, &route);
		if (   existing
		    && !array_get_ip4_route (plat_routes, existing->ifindex, existing)) {
			/* The route that should already exist is not there.
			 * Try to add it. */
			nm_platform_ip4_route_add (NM_PLATFORM_GET,
			                           existing->ifindex,
			                           existing->source,
			                           existing->network,
			                           existing->plen,
			                           existing->gateway,
			                           0,
			                           existing->metric,
			                           existing->mss);

			/* It's now hopefully in platform. Take a note so that we
			 * don't attempt to add it again. */
			g_array_append_val (plat_routes, *existing);
		}

		if (route.ifindex == ifindex) {
			/* Clean up. */
			nm_platform_ip4_route_delete (NM_PLATFORM_GET,
			                              route.ifindex,
			                              route.network,
			                              route.plen,
			                              route.metric);
		}
	}

	if (!known_routes)
		return TRUE;

	/* Add missing routes */
	for (i_type = 0, success = TRUE; i_type < 2 && success; i_type++) {
		for (i = 0; i < known_routes->len && success; i++) {
			known_route = &g_array_index (known_routes, NMPlatformIP4Route, i);

			g_assert (known_route->ifindex);

			if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT (known_route))
				continue;

			if ((known_route->gateway == 0) ^ (i_type == 0)) {
				/* Make two runs over the list of routes. On the first, only add
				 * device routes, on the second the others (gateway routes). */
				continue;
			}

			/* Ignore routes that already exist */
			if (!array_get_ip4_route (routes, 0, known_route)) {
				success = nm_platform_ip4_route_add (NM_PLATFORM_GET,
				                                     known_route->ifindex,
				                                     known_route->source,
				                                     known_route->network,
				                                     known_route->plen,
				                                     known_route->gateway,
				                                     0,
				                                     known_route->metric,
				                                     known_route->mss);
				if (!success && known_route->source < NM_IP_CONFIG_SOURCE_USER) {
					nm_log_dbg (LOGD_CORE, "ignore error adding IPv4 route to kernel: %s",
					                       nm_platform_ip4_route_to_string (known_route));
					success = TRUE;
				}
			}

			if (!array_get_ip4_route (routes, known_route->ifindex, known_route))
				g_array_append_val (routes, *known_route);
		}
	}

	return success;
}

/**
 * nm_route_manager_ip6_route_sync:
 * @ifindex: Interface index
 * @known_routes: List of routes
 *
 * A convenience function to synchronize routes for a specific interface
 * with the least possible disturbance. It simply removes routes that are
 * not listed and adds routes that are.
 * Default routes are ignored (both in @known_routes and those already
 * configured on the device).
 *
 * Returns: %TRUE on success.
 */
gboolean
nm_route_manager_ip6_route_sync (NMRouteManager *self, int ifindex, const GArray *known_routes)
{
	NMRouteManagerPrivate *priv = NM_ROUTE_MANAGER_GET_PRIVATE (self);
	GArray *plat_routes, *routes = priv->ip6_routes;
	NMPlatformIP6Route route;
	const NMPlatformIP6Route *known_route;
	const NMPlatformIP6Route *existing;
	gboolean success;
	int i, i_type;

	/* Learn about routes that platform knows but we don't. */
	plat_routes = nm_platform_ip6_route_get_all (NM_PLATFORM_GET, 0, NM_PLATFORM_GET_ROUTE_MODE_NO_DEFAULT);
	for (i = 0; i < plat_routes->len; i++) {
		existing = &g_array_index (plat_routes, NMPlatformIP6Route, i);
		if (!array_get_ip6_route (routes, existing->ifindex, existing))
			g_array_append_val (routes, *existing);
	}

	for (i = 0; i < routes->len;) {
		route = g_array_index (routes, NMPlatformIP6Route, i);

		if (route.ifindex == ifindex) {
			/* Our route. Keep it? */
			if (array_get_ip6_route (known_routes, route.ifindex, &route)) {
				i++;
				continue;
			}

			g_array_remove_index (routes, i);
		} else {
			i++;
		}

		existing = array_get_ip6_route (routes, 0, &route);
		if (    existing
		    && !array_get_ip6_route (plat_routes, existing->ifindex, existing)) {
			/* The route that should already exist is not there.
			 * Try to add it. */
			nm_platform_ip6_route_add (NM_PLATFORM_GET,
			                           existing->ifindex,
			                           existing->source,
			                           existing->network,
			                           existing->plen,
			                           existing->gateway,
			                           existing->metric,
			                           existing->mss);

			/* It's now hopefully in platform. Take a note so that we
			 * don't attempt to add it again. */
			g_array_append_val (plat_routes, *existing);
		}

		if (route.ifindex == ifindex) {
			/* Clean up. */
			nm_platform_ip6_route_delete (NM_PLATFORM_GET,
			                              route.ifindex,
			                              route.network,
			                              route.plen,
			                              route.metric);
		}
	}

	if (!known_routes)
		return TRUE;

	/* Add missing routes */
	for (i_type = 0, success = TRUE; i_type < 2 && success; i_type++) {
		for (i = 0; i < known_routes->len && success; i++) {
			known_route = &g_array_index (known_routes, NMPlatformIP6Route, i);

			g_assert (known_route->ifindex);

			if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT (known_route))
				continue;

			if (IN6_IS_ADDR_UNSPECIFIED (&known_route->gateway) ^ (i_type == 0)) {
				/* Make two runs over the list of routes. On the first, only add
				 * device routes, on the second the others (gateway routes). */
				continue;
			}

			/* Ignore routes that already exist */
			if (!array_get_ip6_route (routes, 0, known_route)) {
				success = nm_platform_ip6_route_add (NM_PLATFORM_GET,
				                                     known_route->ifindex,
				                                     known_route->source,
				                                     known_route->network,
				                                     known_route->plen,
				                                     known_route->gateway,
				                                     known_route->metric,
				                                     known_route->mss);
				if (!success && known_route->source < NM_IP_CONFIG_SOURCE_USER) {
					nm_log_dbg (LOGD_CORE, "ignore error adding IPv6 route to kernel: %s",
					                       nm_platform_ip6_route_to_string (known_route));
					success = TRUE;
				}
			}

			if (!array_get_ip6_route (routes, known_route->ifindex, known_route))
				g_array_append_val (routes, *known_route);
		}
	}

	return success;
}

gboolean
nm_route_manager_route_flush (NMRouteManager *self, int ifindex)
{
	return    nm_route_manager_ip4_route_sync (self, ifindex, NULL)
	       && nm_route_manager_ip6_route_sync (self, ifindex, NULL);
}

NMRouteManager *
nm_route_manager_get ()
{
	if (G_UNLIKELY (!_instance)) {
		_instance = NM_ROUTE_MANAGER (g_object_new (NM_TYPE_ROUTE_MANAGER, NULL));
		g_object_add_weak_pointer (G_OBJECT (_instance), (gpointer *) &_instance);
	}
	return _instance;
}

static void
nm_route_manager_init (NMRouteManager *self)
{
	NMRouteManagerPrivate *priv = NM_ROUTE_MANAGER_GET_PRIVATE (self);

	priv->ip4_routes = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP4Route));
	priv->ip6_routes = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP6Route));
}

static void
finalize (GObject *object)
{
	NMRouteManagerPrivate *priv = NM_ROUTE_MANAGER_GET_PRIVATE (object);

	g_array_free (priv->ip4_routes, TRUE);
	g_array_free (priv->ip6_routes, TRUE);

	G_OBJECT_CLASS (nm_route_manager_parent_class)->finalize (object);
}

static void
nm_route_manager_class_init (NMRouteManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMRouteManagerPrivate));

	/* virtual methods */
	object_class->finalize = finalize;
}
