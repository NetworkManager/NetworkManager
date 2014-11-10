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
 * Copyright (C) 2014 Red Hat, Inc.
 */


#include "config.h"

#include "nm-default-route-manager.h"

#include "string.h"

#include "nm-logging.h"
#include "nm-device.h"
#include "nm-vpn-connection.h"
#include "nm-platform.h"
#include "nm-manager.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-activation-request.h"

typedef struct {
	GPtrArray *entries_ip4;
	GPtrArray *entries_ip6;
} NMDefaultRouteManagerPrivate;

#define NM_DEFAULT_ROUTE_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEFAULT_ROUTE_MANAGER, NMDefaultRouteManagerPrivate))

G_DEFINE_TYPE (NMDefaultRouteManager, nm_default_route_manager, G_TYPE_OBJECT)

static NMDefaultRouteManager *_instance;

#define _LOG(level, addr_family, ...) \
    G_STMT_START { \
        int __addr_family = (addr_family); \
        guint64 __domain = __addr_family == AF_INET ? LOGD_IP4 : LOGD_IP6; \
        \
        if (nm_logging_enabled ((level), (__domain))) { \
            char __ch = __addr_family == AF_INET ? '4' : '6'; \
            char __prefix[30] = "default-route"; \
            \
            if ((self) != _instance) \
                g_snprintf (__prefix, sizeof (__prefix), "default-route%c[%p]", __ch, (self)); \
            else \
                __prefix[STRLEN ("default-route")] = __ch; \
            nm_log ((level), (__domain), \
                    "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                    __prefix _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        } \
    } G_STMT_END

#define _LOGD(addr_family, ...)      _LOG (LOGL_DEBUG, addr_family, __VA_ARGS__)
#define _LOGI(addr_family, ...)      _LOG (LOGL_INFO , addr_family, __VA_ARGS__)
#define _LOGW(addr_family, ...)      _LOG (LOGL_WARN , addr_family, __VA_ARGS__)
#define _LOGE(addr_family, ...)      _LOG (LOGL_ERR  , addr_family, __VA_ARGS__)

#define LOG_ENTRY_FMT  "entry[%u/%s:%p:%s]"
#define LOG_ENTRY_ARGS(entry_idx, entry) \
		entry_idx, \
		NM_IS_DEVICE (entry->source.pointer) ? "dev" : "vpn", \
		entry->source.pointer, \
		NM_IS_DEVICE (entry->source.pointer) ? nm_device_get_iface (entry->source.device) : nm_vpn_connection_get_connection_id (entry->source.vpn)

/***********************************************************************************/

typedef struct {
	union {
		void *pointer;
		GObject *object;
		NMDevice *device;
		NMVpnConnection *vpn;
	} source;
	NMPlatformIPXRoute route;
	gboolean synced; /* if true, we synced the entry to platform. We don't sync assumed devices */

	/* it makes sense to order sources based on their priority, without
	 * actually adding a default route. This is useful to decide which
	 * DNS server to prefer. never_default entries are not synced to platform. */
	gboolean never_default;

	guint32 effective_metric;
} Entry;

typedef struct {
	int addr_family;
	GPtrArray *(*get_entries) (NMDefaultRouteManagerPrivate *priv);
	const char *(*platform_route_to_string) (const NMPlatformIPRoute *route);
	GArray *(*platform_route_get_all) (int ifindex, NMPlatformGetRouteMode mode);
	gboolean (*platform_route_delete_default) (int ifindex, guint32 metric);
	guint32 (*route_metric_normalize) (guint32 metric);
} VTableIP;

static const VTableIP vtable_ip4, vtable_ip6;

#define VTABLE_IS_IP4 (vtable->addr_family == AF_INET)

static NMPlatformIPRoute *
_vt_route_index (const VTableIP *vtable, GArray *routes, guint index)
{
	if (VTABLE_IS_IP4)
		return (NMPlatformIPRoute *) &g_array_index (routes, NMPlatformIP4Route, index);
	else
		return (NMPlatformIPRoute *) &g_array_index (routes, NMPlatformIP6Route, index);
}

static void
_entry_free (Entry *entry)
{
	if (entry) {
		g_object_unref (entry->source.object);
		g_slice_free (Entry, entry);
	}
}

static Entry *
_entry_find_by_source (GPtrArray *entries, gpointer source, guint *out_idx)
{
	guint i;

	for (i = 0; i < entries->len; i++) {
		Entry *e = g_ptr_array_index (entries, i);

		if (e->source.pointer == source) {
			if (out_idx)
				*out_idx = i;
			return e;
		}
	}

	if (out_idx)
		*out_idx = G_MAXUINT;
	return NULL;
}

static void
_platform_route_sync_add (const VTableIP *vtable, NMDefaultRouteManager *self, guint32 metric)
{
	NMDefaultRouteManagerPrivate *priv = NM_DEFAULT_ROUTE_MANAGER_GET_PRIVATE (self);
	GPtrArray *entries = vtable->get_entries (priv);
	guint i;
	gboolean has_unsynced_entry = FALSE;
	Entry *entry = NULL;
	gboolean success;

	/* Find the entries for the given metric.
	 * The effective metric for synced entries is choosen in a way that it
	 * is unique (except for G_MAXUINT32, where a clash is not solvable). */
	for (i = 0; i < entries->len; i++) {
		Entry *e = g_ptr_array_index (entries, i);

		if (e->never_default)
			continue;

		if (e->effective_metric != metric)
			continue;

		if (e->synced) {
			g_assert (!entry || metric == G_MAXUINT32);
			if (!entry)
				entry = e;
		} else
			has_unsynced_entry = TRUE;
	}

	/* For synced entries, we expect that the metric is chosen uniquely. */
	g_assert (!entry || !has_unsynced_entry || metric == G_MAXUINT32);

	/* we only add the route, if we have an (to be synced) entry for it. */
	if (!entry)
		return;

	if (VTABLE_IS_IP4) {
		success = nm_platform_ip4_route_add (entry->route.rx.ifindex,
		                                     entry->route.rx.source,
		                                     0,
		                                     0,
		                                     entry->route.r4.gateway,
		                                     entry->effective_metric,
		                                     entry->route.rx.mss);
	} else {
		success = nm_platform_ip6_route_add (entry->route.rx.ifindex,
		                                     entry->route.rx.source,
		                                     in6addr_any,
		                                     0,
		                                     entry->route.r6.gateway,
		                                     entry->effective_metric,
		                                     entry->route.rx.mss);
	}
	if (!success) {
		_LOGW (vtable->addr_family, "failed to add default route %s with effective metric %u",
		       vtable->platform_route_to_string (&entry->route.rx), (guint) entry->effective_metric);
	}
}

static void
_platform_route_sync_flush (const VTableIP *vtable, NMDefaultRouteManager *self)
{
	NMDefaultRouteManagerPrivate *priv = NM_DEFAULT_ROUTE_MANAGER_GET_PRIVATE (self);
	GPtrArray *entries = vtable->get_entries (priv);
	GArray *routes;
	guint i, j;

	/* prune all other default routes from this device. */
	routes = vtable->platform_route_get_all (0, NM_PLATFORM_GET_ROUTE_MODE_ONLY_DEFAULT);

	for (i = 0; i < routes->len; i++) {
		const NMPlatformIPRoute *route;
		gboolean has_ifindex_synced = FALSE;
		Entry *entry = NULL;

		route = _vt_route_index (vtable, routes, i);

		/* look at all entires and see if the route for this ifindex pair is
		 * a known entry. */
		for (j = 0; j < entries->len; j++) {
			Entry *e = g_ptr_array_index (entries, j);

			if (e->never_default)
				continue;

			if (   e->route.rx.ifindex == route->ifindex
			    && e->synced) {
				has_ifindex_synced = TRUE;
				if (e->effective_metric == route->metric)
					entry = e;
			}
		}

		/* we only delete the route if we don't have a matching entry,
		 * and there is at least one entry that references this ifindex
		 * (indicating that the ifindex is managed by us -- not assumed).
		 *
		 * Otherwise, don't delete the route because it's configured
		 * externally (and will be assumed -- or already is assumed).
		 */
		if (has_ifindex_synced && !entry)
			vtable->platform_route_delete_default (route->ifindex, route->metric);
	}
	g_array_free (routes, TRUE);
}

static int
_sort_entries_cmp (gconstpointer a, gconstpointer b, gpointer user_data)
{
	guint32 m_a, m_b;
	const Entry *e_a = *((const Entry **) a);
	const Entry *e_b = *((const Entry **) b);

	/* when comparing routes, we consider the (original) metric. */
	m_a = e_a->route.rx.metric;
	m_b = e_b->route.rx.metric;

	/* we normalize route.metric already in _ipx_update_default_route().
	 * so we can just compare the metrics numerically */

	if (m_a != m_b)
		return (m_a < m_b) ? -1 : 1;

	/* If the metrics are equal, we prefer the one that is !never_default */
	if (!!e_a->never_default != !!e_b->never_default)
		return e_a->never_default ? 1 : -1;

	/* If the metrics are equal, we prefer the one that is assumed (!synced).
	 * Entries that we sync, can be modified so that only the best
	 * entry has a (deterministically) lowest metric.
	 * With assumed devices we cannot increase/change the metric.
	 * For example: two devices, both metric 0. One is assumed the other is
	 * synced.
	 * If we would choose the synced entry as best, we cannot
	 * increase the metric of the assumed one and we would have non-determinism.
	 * If we instead prefer the assumed device, we can increase the metric
	 * of the synced device and the assumed device is (deterministically)
	 * prefered.
	 * If both devices are assumed, we also have non-determinism, but also
	 * we don't reorder either.
	 */
	if (!!e_a->synced != !!e_b->synced)
		return e_a->synced ? 1 : -1;

	/* otherwise, do not reorder */
	return 0;
}

static void
_resync_all (const VTableIP *vtable, NMDefaultRouteManager *self, const Entry *changed_entry, const Entry *old_entry)
{
	NMDefaultRouteManagerPrivate *priv = NM_DEFAULT_ROUTE_MANAGER_GET_PRIVATE (self);
	Entry *entry;
	guint i;
	gint64 last_metric = -1;
	guint32 expected_metric;
	GPtrArray *entries;
	GHashTableIter iter;
	gpointer ptr;
	GHashTable *changed_metrics = g_hash_table_new (NULL, NULL);

	entries = vtable->get_entries (priv);

	if (old_entry && old_entry->synced) {
		/* The old version obviously changed. */
		g_hash_table_add (changed_metrics, GUINT_TO_POINTER (old_entry->effective_metric));
	}

	/* first iterate over all entries and adjust the effective metrics. */
	for (i = 0; i < entries->len; i++) {
		entry = g_ptr_array_index (entries, i);

		g_assert (entry != old_entry);

		if (entry->never_default)
			continue;

		if (!entry->synced) {
			last_metric = MAX (last_metric, (gint64) entry->effective_metric);
			continue;
		}

		expected_metric = entry->route.rx.metric;
		if ((gint64) expected_metric <= last_metric)
			expected_metric = last_metric == G_MAXUINT32 ? G_MAXUINT32 : last_metric + 1;

		if (changed_entry == entry) {
			/* for the changed entry, the previous metric was either old_entry->effective_metric,
			 * or none. Hence, we only have to remember what is going to change. */
			g_hash_table_add (changed_metrics, GUINT_TO_POINTER (expected_metric));
			if (old_entry) {
				_LOGD (vtable->addr_family, LOG_ENTRY_FMT": update %s (%u -> %u)", LOG_ENTRY_ARGS (i, entry),
				       vtable->platform_route_to_string (&entry->route.rx), (guint) old_entry->effective_metric,
				       (guint) expected_metric);
			} else {
				_LOGD (vtable->addr_family, LOG_ENTRY_FMT": add %s (%u)", LOG_ENTRY_ARGS (i, entry),
				       vtable->platform_route_to_string (&entry->route.rx), (guint) expected_metric);
			}
		} else if (entry->effective_metric != expected_metric) {
			g_hash_table_add (changed_metrics, GUINT_TO_POINTER (entry->effective_metric));
			g_hash_table_add (changed_metrics, GUINT_TO_POINTER (expected_metric));
			_LOGD (vtable->addr_family, LOG_ENTRY_FMT": resync metric %s (%u -> %u)", LOG_ENTRY_ARGS (i, entry),
			       vtable->platform_route_to_string (&entry->route.rx), (guint) entry->effective_metric,
			       (guint) expected_metric);
		}

		entry->effective_metric = expected_metric;
		last_metric = expected_metric;
	}

	g_hash_table_iter_init (&iter, changed_metrics);
	while (g_hash_table_iter_next (&iter, &ptr, NULL))
		_platform_route_sync_add (vtable, self, GPOINTER_TO_UINT (ptr));
	_platform_route_sync_flush (vtable, self);

	g_hash_table_unref (changed_metrics);
}

static void
_entry_at_idx_update (const VTableIP *vtable, NMDefaultRouteManager *self, guint entry_idx, const Entry *old_entry)
{
	NMDefaultRouteManagerPrivate *priv = NM_DEFAULT_ROUTE_MANAGER_GET_PRIVATE (self);
	Entry *entry;
	GPtrArray *entries;

	entries = vtable->get_entries (priv);
	g_assert (entry_idx < entries->len);

	entry = g_ptr_array_index (entries, entry_idx);

	g_assert (   !old_entry
	          || (entry->source.pointer == old_entry->source.pointer && entry->route.rx.ifindex == old_entry->route.rx.ifindex));

	if (!entry->synced) {
		entry->effective_metric = entry->route.rx.metric;
		_LOGD (vtable->addr_family, LOG_ENTRY_FMT": %s %s%s",
		       LOG_ENTRY_ARGS (entry_idx, entry),
		       old_entry ? "update" : "add",
		       vtable->platform_route_to_string (&entry->route.rx),
		       entry->never_default ? " (never-default)" : (entry->synced ? "" : " (not synced)"));
	}

	g_ptr_array_sort_with_data (entries, _sort_entries_cmp, NULL);

	_resync_all (vtable, self, entry, old_entry);
}

static void
_entry_at_idx_remove (const VTableIP *vtable, NMDefaultRouteManager *self, guint entry_idx)
{
	NMDefaultRouteManagerPrivate *priv = NM_DEFAULT_ROUTE_MANAGER_GET_PRIVATE (self);
	Entry *entry;
	GPtrArray *entries;

	entries = vtable->get_entries (priv);

	g_assert (entry_idx < entries->len);

	entry = g_ptr_array_index (entries, entry_idx);

	_LOGD (vtable->addr_family, LOG_ENTRY_FMT": remove %s (%u%s)", LOG_ENTRY_ARGS (entry_idx, entry),
	       vtable->platform_route_to_string (&entry->route.rx), (guint) entry->effective_metric,
	       entry->synced ? "" : ", not synced");

	/* Remove the entry from the list (but don't free it yet) */
	g_ptr_array_index (entries, entry_idx) = NULL;
	g_ptr_array_remove_index (entries, entry_idx);

	_resync_all (vtable, self, NULL, entry);

	_entry_free (entry);
}

/***********************************************************************************/

static void
_ipx_update_default_route (const VTableIP *vtable, NMDefaultRouteManager *self, gpointer source)
{
	NMDefaultRouteManagerPrivate *priv;
	Entry *entry;
	guint entry_idx;
	const NMPlatformIPRoute *default_route = NULL;
	NMPlatformIPXRoute rt;
	int ip_ifindex;
	GPtrArray *entries;
	NMDevice *device = NULL;
	NMVpnConnection *vpn = NULL;
	gboolean never_default = FALSE;
	gboolean synced;

	g_return_if_fail (NM_IS_DEFAULT_ROUTE_MANAGER (self));
	if (NM_IS_DEVICE (source))
		device = source;
	else if (NM_IS_VPN_CONNECTION (source))
		vpn = source;
	else
		g_return_if_reached ();

	if (device)
		ip_ifindex = nm_device_get_ip_ifindex (device);
	else {
		ip_ifindex = nm_vpn_connection_get_ip_ifindex (vpn);

		if (ip_ifindex <= 0) {
			NMDevice *parent = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (vpn));

			if (parent)
				ip_ifindex = nm_device_get_ip_ifindex (parent);
		}
	}

	priv = NM_DEFAULT_ROUTE_MANAGER_GET_PRIVATE (self);

	entries = vtable->get_entries (priv);
	entry = _entry_find_by_source (entries, source, &entry_idx);

	if (   entry
	    && entry->route.rx.ifindex != ip_ifindex) {
		/* Strange... the ifindex changed... Remove the device and start again. */
		_LOGD (vtable->addr_family, "ifindex of "LOG_ENTRY_FMT" changed: %d -> %d",
		       LOG_ENTRY_ARGS (entry_idx, entry),
		       entry->route.rx.ifindex, ip_ifindex);

		g_object_freeze_notify (G_OBJECT (self));
		_entry_at_idx_remove (vtable, self, entry_idx);
		g_assert (!_entry_find_by_source (entries, source, NULL));
		_ipx_update_default_route (vtable, self, source);
		g_object_thaw_notify (G_OBJECT (self));
		return;
	}

	/* get the @default_route from the device. */
	if (ip_ifindex > 0) {
		if (device) {
			if (VTABLE_IS_IP4)
				default_route = (const NMPlatformIPRoute *) nm_device_get_ip4_default_route (device);
			else
				default_route = (const NMPlatformIPRoute *) nm_device_get_ip6_default_route (device);
		} else {
			NMConnection *connection = nm_active_connection_get_connection ((NMActiveConnection *) vpn);

			if (   connection
			    && nm_vpn_connection_get_vpn_state (vpn) == NM_VPN_CONNECTION_STATE_ACTIVATED) {

				memset (&rt, 0, sizeof (rt));
				if (VTABLE_IS_IP4) {
					NMIP4Config *vpn_config;

					vpn_config = nm_vpn_connection_get_ip4_config (vpn);
					if (vpn_config) {
						never_default = nm_ip4_config_get_never_default (vpn_config);
						rt.r4.ifindex = ip_ifindex;
						rt.r4.source = NM_IP_CONFIG_SOURCE_VPN;
						rt.r4.gateway = nm_vpn_connection_get_ip4_internal_gateway (vpn);
						rt.r4.metric = nm_vpn_connection_get_ip4_route_metric (vpn);
						rt.r4.mss = nm_ip4_config_get_mss (vpn_config);
						default_route = &rt.rx;
					}
				} else {
					NMIP6Config *vpn_config;

					vpn_config = nm_vpn_connection_get_ip6_config (vpn);
					if (vpn_config) {
						const struct in6_addr *int_gw = nm_vpn_connection_get_ip6_internal_gateway (vpn);

						never_default = nm_ip6_config_get_never_default (vpn_config);
						rt.r6.ifindex = ip_ifindex;
						rt.r6.source = NM_IP_CONFIG_SOURCE_VPN;
						rt.r6.gateway = int_gw ? *int_gw : in6addr_any;
						rt.r6.metric = nm_vpn_connection_get_ip6_route_metric (vpn);
						rt.r6.mss = nm_ip6_config_get_mss (vpn_config);
						default_route = &rt.rx;
					}
				}
			}
		}
	}
	g_assert (!default_route || default_route->plen == 0);

	/* if the source is never_default or the device uses an assumed connection,
	 * we don't sync the route. */
	synced = !never_default && (!device || !nm_device_uses_assumed_connection (device));

	if (!entry && !default_route)
		/* nothing to do */;
	else if (!entry) {
		/* add */
		entry = g_slice_new0 (Entry);
		entry->source.object = g_object_ref (source);

		if (VTABLE_IS_IP4)
			entry->route.r4 = *((const NMPlatformIP4Route *) default_route);
		else
			entry->route.r6 = *((const NMPlatformIP6Route *) default_route);

		/* only use normalized metrics */
		entry->route.rx.metric = vtable->route_metric_normalize (entry->route.rx.metric);
		entry->route.rx.ifindex = ip_ifindex;
		entry->never_default = never_default;
		entry->effective_metric = entry->route.rx.metric;
		entry->synced = synced;

		g_ptr_array_add (entries, entry);
		_entry_at_idx_update (vtable, self, entries->len - 1, NULL);
	} else if (default_route) {
		/* update */
		Entry old_entry, new_entry;

		new_entry = *entry;
		if (VTABLE_IS_IP4)
			new_entry.route.r4 = *((const NMPlatformIP4Route *) default_route);
		else
			new_entry.route.r6 = *((const NMPlatformIP6Route *) default_route);
		/* only use normalized metrics */
		new_entry.route.rx.metric = vtable->route_metric_normalize (new_entry.route.rx.metric);
		new_entry.route.rx.ifindex = ip_ifindex;
		new_entry.never_default = never_default;
		new_entry.synced = synced;

		if (memcmp (entry, &new_entry, sizeof (new_entry)) == 0)
			return;

		old_entry = *entry;
		*entry = new_entry;
		_entry_at_idx_update (vtable, self, entry_idx, &old_entry);
	} else {
		/* delete */
		_entry_at_idx_remove (vtable, self, entry_idx);
	}
}

void
nm_default_route_manager_ip4_update_default_route (NMDefaultRouteManager *self, gpointer source)
{
	_ipx_update_default_route (&vtable_ip4, self, source);
}

void
nm_default_route_manager_ip6_update_default_route (NMDefaultRouteManager *self, gpointer source)
{
	_ipx_update_default_route (&vtable_ip6, self, source);
}

/***********************************************************************************/

static gboolean
_ipx_connection_has_default_route (const VTableIP *vtable, NMDefaultRouteManager *self, NMConnection *connection)
{
	const char *method;
	NMSettingIPConfig *s_ip;

	g_return_val_if_fail (NM_IS_DEFAULT_ROUTE_MANAGER (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	if (VTABLE_IS_IP4)
		s_ip = nm_connection_get_setting_ip4_config (connection);
	else
		s_ip = nm_connection_get_setting_ip6_config (connection);
	if (!s_ip || nm_setting_ip_config_get_never_default (s_ip))
		return FALSE;

	if (VTABLE_IS_IP4) {
		method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
		if (   !method
		    || !strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)
		    || !strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL))
			return FALSE;
	} else {
		method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);
		if (   !method
		    || !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE)
		    || !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL))
			return FALSE;
	}

	return TRUE;
}

gboolean
nm_default_route_manager_ip4_connection_has_default_route (NMDefaultRouteManager *self, NMConnection *connection)
{
	return _ipx_connection_has_default_route (&vtable_ip4, self, connection);
}

gboolean
nm_default_route_manager_ip6_connection_has_default_route (NMDefaultRouteManager *self, NMConnection *connection)
{
	return _ipx_connection_has_default_route (&vtable_ip6, self, connection);
}

/***********************************************************************************/

static NMDevice *
_ipx_get_best_device (const VTableIP *vtable, NMDefaultRouteManager *self, const GSList *devices)
{
	NMDefaultRouteManagerPrivate *priv;
	GPtrArray *entries;
	guint i;

	g_return_val_if_fail (NM_IS_DEFAULT_ROUTE_MANAGER (self), NULL);

	if (!devices)
		return NULL;

	priv = NM_DEFAULT_ROUTE_MANAGER_GET_PRIVATE (self);
	entries = vtable->get_entries (priv);

	for (i = 0; i < entries->len; i++) {
		Entry *entry = g_ptr_array_index (entries, i);

		if (!NM_IS_DEVICE (entry->source.pointer))
			continue;

		g_assert (!entry->never_default);

		if (g_slist_find ((GSList *) devices, entry->source.device))
			return entry->source.pointer;
	}
	return NULL;
}

/** _ipx_get_best_activating_device:
 * @vtable: the virtual table
 * @self: #NMDefaultRouteManager
 * @devices: list of devices to be searched. Only devices from this list will be considered
 * @fully_activated: if #TRUE, only search for devices that are fully activated. Otherwise,
 *   search if there is a best device going to be activated. In the latter case, this will
 *   return NULL if the best device is already activated.
 * @preferred_device: if not-NULL, this device is preferred if there are more devices with
 *   the same priority.
 **/
static NMDevice *
_ipx_get_best_activating_device (const VTableIP *vtable, NMDefaultRouteManager *self, const GSList *devices, NMDevice *preferred_device)
{
	NMDefaultRouteManagerPrivate *priv;
	const GSList *iter;
	NMDevice *best_device = NULL;
	guint32 best_prio = G_MAXUINT32;
	NMDevice *best_activated_device;

	g_return_val_if_fail (NM_IS_DEFAULT_ROUTE_MANAGER (self), NULL);

	priv = NM_DEFAULT_ROUTE_MANAGER_GET_PRIVATE (self);

	best_activated_device = _ipx_get_best_device (vtable, self, devices);

	for (iter = devices; iter; iter = g_slist_next (iter)) {
		NMDevice *device = NM_DEVICE (iter->data);
		guint32 prio;
		Entry *entry;

		entry = _entry_find_by_source (vtable->get_entries (priv), device, NULL);

		if (entry) {
			/* of all the device that have an entry, we already know that best_activated_device
			 * is the best. entry cannot be better. */
			if (entry->source.device != best_activated_device)
				continue;
			prio = entry->effective_metric;
		} else {
			NMDeviceState state = nm_device_get_state (device);

			if (   state <= NM_DEVICE_STATE_DISCONNECTED
			    || state >= NM_DEVICE_STATE_DEACTIVATING)
				continue;

			if (!_ipx_connection_has_default_route (vtable, self, nm_device_get_connection (device)))
				continue;

			prio = nm_device_get_ip4_route_metric (device);
		}
		prio = vtable->route_metric_normalize (prio);

		if (   !best_device
		    || prio < best_prio
			|| (prio == best_prio && preferred_device == device)) {
			best_device = device;
			best_prio = prio;
		}
	}

	/* There's only a best activating device if the best device
	 * among all activating and already-activated devices is a
	 * still-activating one.
	 */
	if (best_device && nm_device_get_state (best_device) >= NM_DEVICE_STATE_SECONDARIES)
		return NULL;
	return best_device;
}

NMDevice *
nm_default_route_manager_ip4_get_best_device (NMDefaultRouteManager *self, const GSList *devices, gboolean fully_activated, NMDevice *preferred_device)
{
	if (fully_activated)
		return _ipx_get_best_device (&vtable_ip4, self, devices);
	else
		return _ipx_get_best_activating_device (&vtable_ip4, self, devices, preferred_device);
}

NMDevice *
nm_default_route_manager_ip6_get_best_device (NMDefaultRouteManager *self, const GSList *devices, gboolean fully_activated, NMDevice *preferred_device)
{
	if (fully_activated)
		return _ipx_get_best_device (&vtable_ip6, self, devices);
	else
		return _ipx_get_best_activating_device (&vtable_ip6, self, devices, preferred_device);
}

/***********************************************************************************/

static gpointer
_ipx_get_best_config (const VTableIP *vtable,
                      NMDefaultRouteManager *self,
                      gboolean ignore_never_default,
                      const char **out_ip_iface,
                      NMActiveConnection **out_ac,
                      NMDevice **out_device,
                      NMVpnConnection **out_vpn)
{
	NMDefaultRouteManagerPrivate *priv;
	GPtrArray *entries;
	guint i;
	gpointer config_result = NULL;

	g_return_val_if_fail (NM_IS_DEFAULT_ROUTE_MANAGER (self), NULL);

	if (out_ip_iface)
		*out_ip_iface = NULL;
	if (out_ac)
		*out_ac = NULL;
	if (out_device)
		*out_device = NULL;
	if (out_vpn)
		*out_vpn = NULL;

	priv = NM_DEFAULT_ROUTE_MANAGER_GET_PRIVATE (self);

	g_return_val_if_fail (NM_IS_DEFAULT_ROUTE_MANAGER (self), NULL);

	priv = NM_DEFAULT_ROUTE_MANAGER_GET_PRIVATE (self);
	entries = vtable->get_entries (priv);

	for (i = 0; i < entries->len; i++) {
		Entry *entry = g_ptr_array_index (entries, i);

		if (!NM_IS_DEVICE (entry->source.pointer)) {
			NMVpnConnection *vpn = NM_VPN_CONNECTION (entry->source.vpn);

			if (entry->never_default && !ignore_never_default)
				continue;

			if (VTABLE_IS_IP4)
				config_result = nm_vpn_connection_get_ip4_config (vpn);
			else
				config_result = nm_vpn_connection_get_ip6_config (vpn);
			g_assert (config_result);

			if (out_vpn)
				*out_vpn = vpn;
			if (out_ac)
				*out_ac = NM_ACTIVE_CONNECTION (vpn);
			if (out_ip_iface)
				*out_ip_iface = nm_vpn_connection_get_ip_iface (vpn);
		} else {
			NMDevice *device = entry->source.device;
			NMActRequest *req;

			if (VTABLE_IS_IP4)
				config_result = nm_device_get_ip4_config (device);
			else
				config_result = nm_device_get_ip6_config (device);
			g_assert (config_result);
			req = nm_device_get_act_request (device);
			g_assert (req);

			if (out_device)
				*out_device = device;
			if (out_ac)
				*out_ac = NM_ACTIVE_CONNECTION (req);
			if (out_ip_iface)
				*out_ip_iface = nm_device_get_ip_iface (device);
		}
		break;
	}

	return config_result;
}

NMIP4Config *
nm_default_route_manager_ip4_get_best_config (NMDefaultRouteManager *self,
                                              gboolean ignore_never_default,
                                              const char **out_ip_iface,
                                              NMActiveConnection **out_ac,
                                              NMDevice **out_device,
                                              NMVpnConnection **out_vpn)
{
	return _ipx_get_best_config (&vtable_ip4,
	                             self,
	                             ignore_never_default,
	                             out_ip_iface,
	                             out_ac,
	                             out_device,
	                             out_vpn);
}

NMIP6Config *
nm_default_route_manager_ip6_get_best_config (NMDefaultRouteManager *self,
                                              gboolean ignore_never_default,
                                              const char **out_ip_iface,
                                              NMActiveConnection **out_ac,
                                              NMDevice **out_device,
                                              NMVpnConnection **out_vpn)
{
	return _ipx_get_best_config (&vtable_ip6,
	                             self,
	                             ignore_never_default,
	                             out_ip_iface,
	                             out_ac,
	                             out_device,
	                             out_vpn);
}

/***********************************************************************************/

static GPtrArray *
_v4_get_entries (NMDefaultRouteManagerPrivate *priv)
{
	return priv->entries_ip4;
}

static GPtrArray *
_v6_get_entries (NMDefaultRouteManagerPrivate *priv)
{
	return priv->entries_ip6;
}

static gboolean
_v4_platform_route_delete_default (int ifindex, guint32 metric)
{
	return nm_platform_ip4_route_delete (ifindex, 0, 0, metric);
}

static gboolean
_v6_platform_route_delete_default (int ifindex, guint32 metric)
{
	return nm_platform_ip6_route_delete (ifindex, in6addr_any, 0, metric);
}

static guint32
_v4_route_metric_normalize (guint32 metric)
{
	return metric;
}

static const VTableIP vtable_ip4 = {
	.addr_family                    = AF_INET,
	.get_entries                    = _v4_get_entries,
	.platform_route_to_string       = (const char *(*)(const NMPlatformIPRoute *)) nm_platform_ip4_route_to_string,
	.platform_route_get_all         = nm_platform_ip4_route_get_all,
	.platform_route_delete_default  = _v4_platform_route_delete_default,
	.route_metric_normalize         = _v4_route_metric_normalize,
};

static const VTableIP vtable_ip6 = {
	.addr_family                    = AF_INET6,
	.get_entries                    = _v6_get_entries,
	.platform_route_to_string       = (const char *(*)(const NMPlatformIPRoute *)) nm_platform_ip6_route_to_string,
	.platform_route_get_all         = nm_platform_ip6_route_get_all,
	.platform_route_delete_default  = _v6_platform_route_delete_default,
	.route_metric_normalize         = nm_utils_ip6_route_metric_normalize,
};

/***********************************************************************************/

NMDefaultRouteManager *
nm_default_route_manager_get ()
{
	if (G_UNLIKELY (!_instance)) {
		_instance = NM_DEFAULT_ROUTE_MANAGER (g_object_new (NM_TYPE_DEFAULT_ROUTE_MANAGER, NULL));
		g_object_add_weak_pointer (G_OBJECT (_instance), (gpointer *) &_instance);
	}
	return _instance;
}

/***********************************************************************************/

static void
nm_default_route_manager_init (NMDefaultRouteManager *self)
{
	NMDefaultRouteManagerPrivate *priv = NM_DEFAULT_ROUTE_MANAGER_GET_PRIVATE (self);

	priv->entries_ip4 = g_ptr_array_new_full (0, (GDestroyNotify) _entry_free);
	priv->entries_ip6 = g_ptr_array_new_full (0, (GDestroyNotify) _entry_free);
}

static void
dispose (GObject *object)
{
	NMDefaultRouteManager *self = NM_DEFAULT_ROUTE_MANAGER (object);
	NMDefaultRouteManagerPrivate *priv = NM_DEFAULT_ROUTE_MANAGER_GET_PRIVATE (self);

	if (priv->entries_ip4) {
		g_ptr_array_free (priv->entries_ip4, TRUE);
		priv->entries_ip4 = NULL;
	}
	if (priv->entries_ip6) {
		g_ptr_array_free (priv->entries_ip6, TRUE);
		priv->entries_ip6 = NULL;
	}

	G_OBJECT_CLASS (nm_default_route_manager_parent_class)->dispose (object);
}

static void
nm_default_route_manager_class_init (NMDefaultRouteManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMDefaultRouteManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
}

