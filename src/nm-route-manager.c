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
#include "gsystem-local-alloc.h"
#include "NetworkManagerUtils.h"

typedef struct {
	guint len;
	NMPlatformIPXRoute *entries[1];
} RouteIndex;

typedef struct {
	GArray *entries;
	RouteIndex *index;
} RouteEntries;

typedef struct {
	NMPlatform *platform;

	RouteEntries ip4_routes;
	RouteEntries ip6_routes;
} NMRouteManagerPrivate;

#define NM_ROUTE_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_ROUTE_MANAGER, NMRouteManagerPrivate))

G_DEFINE_TYPE (NMRouteManager, nm_route_manager, G_TYPE_OBJECT);

NM_DEFINE_SINGLETON_GETTER (NMRouteManager, nm_route_manager_get, NM_TYPE_ROUTE_MANAGER);

/*********************************************************************************************/

typedef struct {
	const NMPlatformVTableRoute *vt;

	/* a compare function for two routes that considers only the fields network/plen,metric. */
	int (*route_id_cmp) (const NMPlatformIPXRoute *r1, const NMPlatformIPXRoute *r2);
} VTableIP;

static const VTableIP vtable_v4, vtable_v6;

#define VTABLE_ROUTE_INDEX(vtable, garray, idx) ((NMPlatformIPXRoute *) &((garray)->data[(idx) * (vtable)->vt->sizeof_route]))

#define VTABLE_IS_DEVICE_ROUTE(vtable, route) ((vtable)->vt->is_ip4 \
                                                ? ((route)->r4.gateway == 0) \
                                                : IN6_IS_ADDR_UNSPECIFIED (&(route)->r6.gateway) )

#define CMP_AND_RETURN_INT(a, b) \
	G_STMT_START { \
		typeof(a) _a = (a), _b = (b); \
		\
		if (_a < _b) \
			return -1; \
		if (_a > _b) \
			return 1; \
	} G_STMT_END

/*********************************************************************************************/

#define _LOG_PREFIX_NAME "route-mgr"

#define _LOG(level, addr_family, ...) \
    G_STMT_START { \
        const int __addr_family = (addr_family); \
        const NMLogLevel __level = (level); \
        const NMLogDomain __domain = __addr_family == AF_INET ? LOGD_IP4 : (__addr_family == AF_INET6 ? LOGD_IP6 : LOGD_IP); \
        \
        if (nm_logging_enabled (__level, __domain)) { \
            char __ch = __addr_family == AF_INET ? '4' : (__addr_family == AF_INET6 ? '6' : '-'); \
            char __prefix[30] = _LOG_PREFIX_NAME; \
            \
            if ((self) != singleton_instance) \
                g_snprintf (__prefix, sizeof (__prefix), "%s%c[%p]", _LOG_PREFIX_NAME, __ch, (self)); \
            else \
                __prefix[STRLEN (_LOG_PREFIX_NAME)] = __ch; \
            _nm_log ((level), (__domain), 0, \
                     "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                     __prefix _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        } \
    } G_STMT_END
#define _LOG_LEVEL_ENABLED(level, addr_family) \
    ({ \
        const int __addr_family = (addr_family); \
        const NMLogLevel __level = (level); \
        const NMLogDomain __domain = __addr_family == AF_INET ? LOGD_IP4 : (__addr_family == AF_INET6 ? LOGD_IP6 : LOGD_IP); \
        \
        nm_logging_enabled (__level, __domain); \
    })

#ifdef NM_MORE_LOGGING
#define _LOGT_ENABLED(addr_family)   _LOG_LEVEL_ENABLED (LOGL_TRACE, addr_family)
#define _LOGT(addr_family, ...)      _LOG (LOGL_TRACE, addr_family, __VA_ARGS__)
#else
#define _LOGT_ENABLED(addr_family)   (FALSE && _LOG_LEVEL_ENABLED (LOGL_TRACE, addr_family))
#define _LOGT(addr_family, ...)      G_STMT_START { if (FALSE) { _LOG (LOGL_TRACE, addr_family, __VA_ARGS__); } } G_STMT_END
#endif

#define _LOGD(addr_family, ...)      _LOG (LOGL_DEBUG, addr_family, __VA_ARGS__)
#define _LOGI(addr_family, ...)      _LOG (LOGL_INFO , addr_family, __VA_ARGS__)
#define _LOGW(addr_family, ...)      _LOG (LOGL_WARN , addr_family, __VA_ARGS__)
#define _LOGE(addr_family, ...)      _LOG (LOGL_ERR  , addr_family, __VA_ARGS__)

/*********************************************************************************************/

#if defined (NM_MORE_ASSERTS) && !defined (G_DISABLE_ASSERT)
inline static void
ASSERT_route_index_valid (const VTableIP *vtable, const GArray *entries, const RouteIndex *index, gboolean unique_ifindexes)
{
	guint i, j;
	int c;
	const NMPlatformIPXRoute *r1, *r2;
	gs_unref_hashtable GHashTable *ptrs = g_hash_table_new (NULL, NULL);
	const NMPlatformIPXRoute *r_first = NULL, *r_last = NULL;

	g_assert (index);

	if (entries)
		g_assert_cmpint (entries->len, ==, index->len);
	else
		g_assert (index->len == 0);

	if (index->len > 0) {
		r_first = VTABLE_ROUTE_INDEX (vtable, entries, 0);
		r_last = VTABLE_ROUTE_INDEX (vtable, entries, index->len - 1);
	}

	/* assert that the @index is valid for the @entries. */

	g_assert (!index->entries[index->len]);
	for (i = 0; i < index->len; i++) {
		r1 = index->entries[i];

		g_assert (r1);
		g_assert (r1 >= r_first);
		g_assert (r1 <= r_last);
		g_assert_cmpint ((((char *) r1) - ((char *) entries->data)) % vtable->vt->sizeof_route, ==, 0);

		g_assert (!g_hash_table_contains (ptrs, (gpointer) r1));
		g_hash_table_add (ptrs, (gpointer) r1);

		for (j = i; j > 0; ) {
			r2 = index->entries[--j];

			c = vtable->route_id_cmp (r1, r2);
			g_assert (c >= 0);
			if (c != 0)
				break;
			if (unique_ifindexes)
				g_assert_cmpint (r1->rx.ifindex, !=, r2->rx.ifindex);
		}
	}
}
#else
#define ASSERT_route_index_valid(vtable, entries, index, unique_ifindexes) G_STMT_START { (void) 0; } G_STMT_END
#endif

/*********************************************************************************************/

static int
_v4_route_id_cmp (const NMPlatformIP4Route *r1, const NMPlatformIP4Route *r2)
{
	CMP_AND_RETURN_INT (r1->plen, r2->plen);
	CMP_AND_RETURN_INT (r1->metric, r2->metric);
	CMP_AND_RETURN_INT (nm_utils_ip4_address_clear_host_address (r1->network, r1->plen),
	                    nm_utils_ip4_address_clear_host_address (r2->network, r2->plen));
	return 0;
}

static int
_v6_route_id_cmp (const NMPlatformIP6Route *r1, const NMPlatformIP6Route *r2)
{
	struct in6_addr n1, n2;

	CMP_AND_RETURN_INT (r1->plen, r2->plen);
	CMP_AND_RETURN_INT (nm_utils_ip6_route_metric_normalize (r1->metric),
	                    nm_utils_ip6_route_metric_normalize (r2->metric));

	nm_utils_ip6_address_clear_host_address (&n1, &r1->network, r1->plen);
	nm_utils_ip6_address_clear_host_address (&n2, &r2->network, r2->plen);
	return memcmp (&n1, &n2, sizeof (n1));
}

/*********************************************************************************************/

static int
_route_index_create_sort (const NMPlatformIPXRoute **p1, const NMPlatformIPXRoute ** p2, const VTableIP *vtable)
{
	return vtable->route_id_cmp (*p1, *p2);
}

static RouteIndex *
_route_index_create (const VTableIP *vtable, const GArray *routes)
{
	RouteIndex *index;
	guint i;
	guint len = routes ? routes->len : 0;

	index = g_malloc (sizeof (RouteIndex) + len * sizeof (NMPlatformIPXRoute *));

	index->len = len;
	for (i = 0; i < len; i++)
		index->entries[i] = VTABLE_ROUTE_INDEX (vtable, routes, i);
	index->entries[i] = NULL;

	/* this is a stable sort, which is very important at this point. */
	g_qsort_with_data (index->entries,
	                   len,
	                   sizeof (NMPlatformIPXRoute *),
	                   (GCompareDataFunc) _route_index_create_sort,
	                   (gpointer) vtable);
	return index;
}

static guint
_route_index_reverse_idx (const VTableIP *vtable, const RouteIndex *index, guint idx_idx, const GArray *routes)
{
	const NMPlatformIPXRoute *r, *r0;
	gssize offset;

	/* reverse the @idx_idx that points into @index, to the corresponding index into the unsorted @routes array. */

	r = index->entries[idx_idx];
	r0 = VTABLE_ROUTE_INDEX (vtable, routes, 0);

	if (vtable->vt->is_ip4)
		offset = &r->r4 - &r0->r4;
	else
		offset = &r->r6 - &r0->r6;
	g_assert (offset >= 0 && offset < index->len);
	g_assert (VTABLE_ROUTE_INDEX (vtable, routes, offset) == r);
	return offset;
}

/*********************************************************************************************/

static gboolean
_route_equals_ignoring_ifindex (const VTableIP *vtable, const NMPlatformIPXRoute *r1, const NMPlatformIPXRoute *r2)
{
	NMPlatformIPXRoute r2_backup;

	if (r1->rx.ifindex != r2->rx.ifindex) {
		memcpy (&r2_backup, r2, vtable->vt->sizeof_route);
		r2_backup.rx.ifindex = r1->rx.ifindex;
		r2 = &r2_backup;
	}
	return vtable->vt->route_cmp (r1, r2) == 0;
}

static NMPlatformIPXRoute *
_get_next_ipx_route (const RouteIndex *index, gboolean start_at_zero, guint *cur_idx, int ifindex)
{
	guint i;

	if (start_at_zero)
		i = 0;
	else
		i = *cur_idx + 1;
	/* Find the next route with matching @ifindex. */
	for (; i < index->len; i++) {
		if (index->entries[i]->rx.ifindex == ifindex) {
			*cur_idx = i;
			return index->entries[i];
		}
	}
	*cur_idx = index->len;
	return NULL;
}

static const NMPlatformIPXRoute *
_get_next_known_route (const VTableIP *vtable, const RouteIndex *index, gboolean start_at_zero, guint *cur_idx)
{
	guint i = 0;
	const NMPlatformIPXRoute *cur = NULL;

	if (!start_at_zero) {
		i = *cur_idx;
		cur = index->entries[i];
		i++;
	}
	/* For @known_routes we expect that all routes have the same @ifindex. This is not enforced however,
	 * the ifindex value of these routes is ignored. */
	for (; i < index->len; i++) {
		const NMPlatformIPXRoute *r = index->entries[i];

		/* skip over default routes. */
		if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT (r))
			continue;

		/* @known_routes should not, but could contain duplicate routes. Skip over them. */
		if (cur && vtable->route_id_cmp (cur, r) == 0)
			continue;

		*cur_idx = i;
		return r;
	}
	*cur_idx = index->len;
	return NULL;
}

static const NMPlatformIPXRoute *
_get_next_plat_route (const RouteIndex *index, gboolean start_at_zero, guint *cur_idx)
{
	if (start_at_zero)
		*cur_idx = 0;
	else
		++*cur_idx;

	/* get next route from the platform index. */
	if (*cur_idx < index->len)
		return index->entries[*cur_idx];
	*cur_idx = index->len;
	return NULL;
}

static int
_sort_indexes_cmp (guint *a, guint *b)
{
	CMP_AND_RETURN_INT (*a, *b);
	g_return_val_if_reached (0);
}

/*********************************************************************************************/

static gboolean
_vx_route_sync (const VTableIP *vtable, NMRouteManager *self, int ifindex, const GArray *known_routes, gboolean ignore_kernel_routes)
{
	NMRouteManagerPrivate *priv = NM_ROUTE_MANAGER_GET_PRIVATE (self);
	GArray *plat_routes;
	RouteEntries *ipx_routes;
	RouteIndex *plat_routes_idx, *known_routes_idx;
	gboolean success = TRUE;
	guint i, i_type;
	GArray *to_delete_indexes = NULL, *to_restore_routes = NULL;
	GPtrArray *to_add_routes = NULL;
	guint i_known_routes, i_plat_routes, i_ipx_routes;
	const NMPlatformIPXRoute *cur_known_route, *cur_plat_route;
	NMPlatformIPXRoute *cur_ipx_route;

	nm_platform_process_events (priv->platform);

	ipx_routes = vtable->vt->is_ip4 ? &priv->ip4_routes : &priv->ip6_routes;
	plat_routes = vtable->vt->route_get_all (priv->platform, ifindex,
	                                         ignore_kernel_routes
	                                             ? NM_PLATFORM_GET_ROUTE_FLAGS_WITH_NON_DEFAULT
	                                             : NM_PLATFORM_GET_ROUTE_FLAGS_WITH_NON_DEFAULT | NM_PLATFORM_GET_ROUTE_FLAGS_WITH_RTPROT_KERNEL);
	plat_routes_idx = _route_index_create (vtable, plat_routes);
	known_routes_idx = _route_index_create (vtable, known_routes);

	ASSERT_route_index_valid (vtable, plat_routes, plat_routes_idx, TRUE);
	ASSERT_route_index_valid (vtable, known_routes, known_routes_idx, FALSE);

	_LOGD (vtable->vt->addr_family, "%3d: sync %u IPv%c routes", ifindex, known_routes_idx->len, vtable->vt->is_ip4 ? '4' : '6');
	if (_LOGT_ENABLED (vtable->vt->addr_family)) {
		for (i = 0; i < known_routes_idx->len; i++) {
			_LOGT (vtable->vt->addr_family, "%3d: sync new route #%u: %s",
			       ifindex, i, vtable->vt->route_to_string (VTABLE_ROUTE_INDEX (vtable, known_routes, i)));
		}
		for (i = 0; i < ipx_routes->index->len; i++)
			_LOGT (vtable->vt->addr_family, "%3d: STATE: has    #%u - %s", ifindex, i, vtable->vt->route_to_string (ipx_routes->index->entries[i]));
	}

	/***************************************************************************
	 * Check which routes are in @known_routes, and update @ipx_routes.
	 *
	 * This first part only updates @ipx_routes to find out what routes must
	 * be added/deleted.
	 **************************************************************************/

	/* iterate over @ipx_routes and @known_routes */
	cur_ipx_route = _get_next_ipx_route (ipx_routes->index, TRUE, &i_ipx_routes, ifindex);
	cur_known_route = _get_next_known_route (vtable, known_routes_idx, TRUE, &i_known_routes);
	while (cur_ipx_route || cur_known_route) {
		int route_id_cmp_result = -1;

		while (   cur_ipx_route
		       && (   !cur_known_route
		           || ((route_id_cmp_result = vtable->route_id_cmp (cur_ipx_route, cur_known_route)) < 0))) {
			/* we have @cur_ipx_route, which is less then @cur_known_route. Hence,
			 * the route does no longer exist in @known_routes */
			if (!to_delete_indexes)
				to_delete_indexes = g_array_new (FALSE, FALSE, sizeof (guint));
			g_array_append_val (to_delete_indexes, i_ipx_routes);

			/* later we will delete @cur_ipx_route. See if @cur_ipx_route was shadowing another route, that
			 * we must restore. */
			if (i_ipx_routes + 1 < ipx_routes->index->len) {
				const NMPlatformIPXRoute *next_route = ipx_routes->index->entries[i_ipx_routes + 1];

				if (vtable->route_id_cmp (cur_ipx_route, next_route) == 0) {
					if (!to_restore_routes)
						to_restore_routes = g_array_new (FALSE, FALSE, vtable->vt->sizeof_route);
					g_array_append_vals (to_restore_routes, next_route, 1);
					g_assert (next_route->rx.ifindex != ifindex);
				}
			}

			/* find the next @cur_ipx_route with matching ifindex. */
			cur_ipx_route = _get_next_ipx_route (ipx_routes->index, FALSE, &i_ipx_routes, ifindex);
		}
		if (   cur_ipx_route
		    && cur_known_route
		    && route_id_cmp_result == 0) {
			if (!_route_equals_ignoring_ifindex (vtable, cur_ipx_route, cur_known_route)) {
				/* The routes match. Update the entry in place. As this is an exact match of primary
				 * fields, this only updates possibly modified fields such as @gateway or @mss.
				 * Modifiying @cur_ipx_route this way does not invalidate @ipx_routes->index. */
				memcpy (cur_ipx_route, cur_known_route, vtable->vt->sizeof_route);
				cur_ipx_route->rx.ifindex = ifindex;
				cur_ipx_route->rx.metric = vtable->vt->metric_normalize (cur_ipx_route->rx.metric);
				_LOGT (vtable->vt->addr_family, "%3d: STATE: update #%u - %s", ifindex, i_ipx_routes, vtable->vt->route_to_string (cur_ipx_route));
			}
		} else if (cur_known_route) {
			g_assert (!cur_ipx_route || route_id_cmp_result > 0);
			/* @cur_known_route is new. We cannot immediately add @cur_known_route to @ipx_routes, because
			 * it would invalidate @ipx_routes->index. Instead remember to add it later. */
			if (!to_add_routes)
				to_add_routes = g_ptr_array_new ();
			g_ptr_array_add (to_add_routes, (gpointer) cur_known_route);
		}

		if (cur_ipx_route && (!cur_known_route || route_id_cmp_result == 0))
			cur_ipx_route = _get_next_ipx_route (ipx_routes->index, FALSE, &i_ipx_routes, ifindex);
		if (cur_known_route)
			cur_known_route = _get_next_known_route (vtable, known_routes_idx, FALSE, &i_known_routes);
	}

	/* Update @ipx_routes with the just learned changes. */
	if (to_delete_indexes || to_add_routes) {
		if (to_delete_indexes) {
			for (i = 0; i < to_delete_indexes->len; i++) {
				guint idx = g_array_index (to_delete_indexes, guint, i);

				_LOGT (vtable->vt->addr_family, "%3d: STATE: delete #%u - %s", ifindex, idx, vtable->vt->route_to_string (ipx_routes->index->entries[idx]));
				g_array_index (to_delete_indexes, guint, i) = _route_index_reverse_idx (vtable, ipx_routes->index, idx, ipx_routes->entries);
			}
			g_array_sort (to_delete_indexes, (GCompareFunc) _sort_indexes_cmp);
			nm_utils_array_remove_at_indexes (ipx_routes->entries, &g_array_index (to_delete_indexes, guint, 0), to_delete_indexes->len);
			g_array_unref (to_delete_indexes);
		}
		if (to_add_routes) {
			for (i = 0; i < to_add_routes->len; i++) {
				NMPlatformIPXRoute *ipx_route;

				g_array_append_vals (ipx_routes->entries, g_ptr_array_index (to_add_routes, i), 1);

				ipx_route = VTABLE_ROUTE_INDEX (vtable, ipx_routes->entries, ipx_routes->entries->len - 1);
				ipx_route->rx.ifindex = ifindex;
				ipx_route->rx.metric = vtable->vt->metric_normalize (ipx_route->rx.metric);

				_LOGT (vtable->vt->addr_family, "%3d: STATE: added  #%u - %s", ifindex, ipx_routes->entries->len - 1, vtable->vt->route_to_string (ipx_route));
			}
			g_ptr_array_unref (to_add_routes);
		}
		g_free (ipx_routes->index);
		ipx_routes->index = _route_index_create (vtable, ipx_routes->entries);
		ASSERT_route_index_valid (vtable, ipx_routes->entries, ipx_routes->index, TRUE);
	}

	/***************************************************************************
	 * Delete routes in platform, that no longer exist in @ipx_routes
	 ***************************************************************************/

	/* iterate over @plat_routes and @ipx_routes */
	cur_plat_route = _get_next_plat_route (plat_routes_idx, TRUE, &i_plat_routes);
	cur_ipx_route = _get_next_ipx_route (ipx_routes->index, TRUE, &i_ipx_routes, ifindex);
	while (cur_plat_route) {
		int route_id_cmp_result = 0;

		g_assert (cur_plat_route->rx.ifindex == ifindex);

		_LOGT (vtable->vt->addr_family, "%3d: platform rt   #%u - %s", ifindex, i_ipx_routes, vtable->vt->route_to_string (cur_plat_route));

		/* skip over @cur_ipx_route that are ordered before @cur_plat_route */
		while (   cur_ipx_route
		       && ((route_id_cmp_result = vtable->route_id_cmp (cur_ipx_route, cur_plat_route)) < 0)) {
			cur_ipx_route = _get_next_ipx_route (ipx_routes->index, FALSE, &i_ipx_routes, ifindex);
		}

		/* if @cur_ipx_route is not equal to @plat_route, the route must be deleted. */
		if (!(cur_ipx_route && route_id_cmp_result == 0))
			vtable->vt->route_delete (priv->platform, ifindex, cur_plat_route);

		cur_plat_route = _get_next_plat_route (plat_routes_idx, FALSE, &i_plat_routes);
	}

	/***************************************************************************
	 * Restore shadowed routes. These routes are on an other @ifindex, but were
	 * shadowed before. Unshadow them now.
	 **************************************************************************/

	if (to_restore_routes) {
		for (i_type = 0; i_type < 2; i_type++) {
			for (i = 0; i < to_restore_routes->len; i++) {
				const NMPlatformIPXRoute *rest_route = VTABLE_ROUTE_INDEX (vtable, to_restore_routes, i);

				if (   (i_type == 0 && !VTABLE_IS_DEVICE_ROUTE (vtable, rest_route))
				    || (i_type == 1 && VTABLE_IS_DEVICE_ROUTE (vtable, rest_route))) {
					/* Make two runs over the list of @to_restore_routes. On the first, only add
					 * device routes, on the second the others (gateway routes). */
					continue;
				}
				vtable->vt->route_add (priv->platform, 0, rest_route);
			}
		}
		g_array_unref (to_restore_routes);
	}

	/***************************************************************************
	 * Sync @ipx_routes for @ifindex to platform
	 **************************************************************************/

	for (i_type = 0; i_type < 2; i_type++) {
		/* iterate (twice) over @ipx_routes and @plat_routes */
		cur_plat_route = _get_next_plat_route (plat_routes_idx, TRUE, &i_plat_routes);
		cur_ipx_route = _get_next_ipx_route (ipx_routes->index, TRUE, &i_ipx_routes, ifindex);
		/* Iterate here over @ipx_routes instead of @known_routes. That is done because
		 * we need to know whether a route is shadowed by another route, and that
		 * requires to look at @ipx_routes. */
		for (; cur_ipx_route; cur_ipx_route = _get_next_ipx_route (ipx_routes->index, FALSE, &i_ipx_routes, ifindex)) {
			int route_id_cmp_result = -1;

			if (   (i_type == 0 && !VTABLE_IS_DEVICE_ROUTE (vtable, cur_ipx_route))
			    || (i_type == 1 && VTABLE_IS_DEVICE_ROUTE (vtable, cur_ipx_route))) {
				/* Make two runs over the list of @ipx_routes. On the first, only add
				 * device routes, on the second the others (gateway routes). */
				continue;
			}

			if (   i_ipx_routes > 0
			    && vtable->route_id_cmp (cur_ipx_route, ipx_routes->index->entries[i_ipx_routes - 1]) == 0) {
				/* @cur_ipx_route is shadewed by another route. */
				continue;
			}

			/* skip over @plat_routes that are ordered before our @cur_ipx_route. */
			while (   cur_plat_route
			       && (route_id_cmp_result = vtable->route_id_cmp (cur_plat_route, cur_ipx_route)) < 0)
				cur_plat_route = _get_next_plat_route (plat_routes_idx, FALSE, &i_plat_routes);

			/* only add the route if we don't have an identical route in @plat_routes,
			 * i.e. if @cur_plat_route is different from @cur_ipx_route. */
			if (   !cur_plat_route
			    || route_id_cmp_result != 0
			    || !_route_equals_ignoring_ifindex (vtable, cur_plat_route, cur_ipx_route)) {

				if (!vtable->vt->route_add (priv->platform, ifindex, cur_ipx_route)) {
					if (cur_ipx_route->rx.source < NM_IP_CONFIG_SOURCE_USER) {
						_LOGD (vtable->vt->addr_family,
						       "ignore error adding IPv%c route to kernel: %s",
						       vtable->vt->is_ip4 ? '4' : '6',
						       vtable->vt->route_to_string (cur_ipx_route));
					} else {
						/* Remember that there was a failure, but for now continue trying
						 * to sync the remaining routes. */
						success = FALSE;
					}
				}
			}
		}
	}

	g_free (known_routes_idx);
	g_free (plat_routes_idx);
	g_array_unref (plat_routes);

	return success;
}

/**
 * nm_route_manager_ip4_route_sync:
 * @ifindex: Interface index
 * @known_routes: List of routes
 * @ignore_kernel_routes: if %TRUE, ignore kernel routes.
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
nm_route_manager_ip4_route_sync (NMRouteManager *self, int ifindex, const GArray *known_routes, gboolean ignore_kernel_routes)
{
	return _vx_route_sync (&vtable_v4, self, ifindex, known_routes, ignore_kernel_routes);
}

/**
 * nm_route_manager_ip6_route_sync:
 * @ifindex: Interface index
 * @known_routes: List of routes
 * @ignore_kernel_routes: if %TRUE, ignore kernel routes.
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
nm_route_manager_ip6_route_sync (NMRouteManager *self, int ifindex, const GArray *known_routes, gboolean ignore_kernel_routes)
{
	return _vx_route_sync (&vtable_v6, self, ifindex, known_routes, ignore_kernel_routes);
}

gboolean
nm_route_manager_route_flush (NMRouteManager *self, int ifindex)
{
	return    nm_route_manager_ip4_route_sync (self, ifindex, NULL, TRUE)
	       && nm_route_manager_ip6_route_sync (self, ifindex, NULL, TRUE);
}

/*********************************************************************************************/

static const VTableIP vtable_v4 = {
	.vt                             = &nm_platform_vtable_route_v4,
	.route_id_cmp                   = (int (*) (const NMPlatformIPXRoute *, const NMPlatformIPXRoute *)) _v4_route_id_cmp,
};

static const VTableIP vtable_v6 = {
	.vt                             = &nm_platform_vtable_route_v6,
	.route_id_cmp                   = (int (*) (const NMPlatformIPXRoute *, const NMPlatformIPXRoute *)) _v6_route_id_cmp,
};

/*********************************************************************************************/

static void
nm_route_manager_init (NMRouteManager *self)
{
	NMRouteManagerPrivate *priv = NM_ROUTE_MANAGER_GET_PRIVATE (self);

	priv->platform = g_object_ref (NM_PLATFORM_GET);

	priv->ip4_routes.entries = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP4Route));
	priv->ip6_routes.entries = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP6Route));
	priv->ip4_routes.index = _route_index_create (&vtable_v4, priv->ip4_routes.entries);
	priv->ip6_routes.index = _route_index_create (&vtable_v6, priv->ip6_routes.entries);
}

static void
dispose (GObject *object)
{
	NMRouteManagerPrivate *priv = NM_ROUTE_MANAGER_GET_PRIVATE (object);

	g_clear_object (&priv->platform);

	G_OBJECT_CLASS (nm_route_manager_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMRouteManagerPrivate *priv = NM_ROUTE_MANAGER_GET_PRIVATE (object);

	g_array_free (priv->ip4_routes.entries, TRUE);
	g_array_free (priv->ip6_routes.entries, TRUE);
	g_free (priv->ip4_routes.index);
	g_free (priv->ip6_routes.index);

	G_OBJECT_CLASS (nm_route_manager_parent_class)->finalize (object);
}

static void
nm_route_manager_class_init (NMRouteManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMRouteManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
	object_class->finalize = finalize;
}
