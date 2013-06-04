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
 * Copyright (C) 2007 Novell, Inc.
 * Copyright (C) 2010 Red Hat, Inc.
 */

#include "nm-call-store.h"
#include "nm-logging.h"

NMCallStore *
nm_call_store_new (void)
{
	/* Maps { DBusGProxy :: GHashTable { DBusGProxyCall :: NULL } } */
	return g_hash_table_new_full (NULL, NULL, NULL, (GDestroyNotify) g_hash_table_destroy);
}

static void
proxy_destroyed_cb (gpointer data, GObject *proxy)
{
	g_hash_table_remove ((NMCallStore *) data, proxy);
}

void
nm_call_store_add (NMCallStore *store,
                   DBusGProxy *proxy,
                   DBusGProxyCall *call)
{
	GHashTable *calls;

	g_return_if_fail (store != NULL);
	g_return_if_fail (proxy != NULL);
	g_return_if_fail (call != NULL);

	calls = g_hash_table_lookup (store, proxy);
	if (!calls) {
		calls = g_hash_table_new (NULL, NULL);
		g_hash_table_insert (store, proxy, calls);
		g_object_weak_ref (G_OBJECT (proxy), proxy_destroyed_cb, store);
	}

	g_hash_table_add (calls, call);
}

void
nm_call_store_remove (NMCallStore *store,
                      DBusGProxy *proxy,
                      DBusGProxyCall *call)
{
	GHashTable *calls;

	g_return_if_fail (store != NULL);
	g_return_if_fail (proxy != NULL);
	g_return_if_fail (call != NULL);

	calls = g_hash_table_lookup (store, proxy);
	if (!calls)
		return;

	g_hash_table_remove (calls, call);
	if (g_hash_table_size (calls) == 0) {
		g_hash_table_remove (store, proxy);
		g_object_weak_unref (G_OBJECT (proxy), proxy_destroyed_cb, store);
	}
}

void
nm_call_store_clear (NMCallStore *store)
{
	DBusGProxy *proxy;
	GHashTable *calls;
	GHashTableIter proxies_iter;

	g_return_if_fail (store != NULL);

	g_hash_table_iter_init (&proxies_iter, store);
	while (g_hash_table_iter_next (&proxies_iter, (gpointer) &proxy, (gpointer) &calls)) {
		GHashTableIter calls_iter;
		DBusGProxyCall *call;

		g_hash_table_iter_init (&calls_iter, calls);
		while (g_hash_table_iter_next (&calls_iter, (gpointer) &call, NULL)) {
			dbus_g_proxy_cancel_call (proxy, call);
			g_hash_table_iter_remove (&calls_iter);
		}
		g_object_weak_unref (G_OBJECT (proxy), proxy_destroyed_cb, store);
		g_hash_table_iter_remove (&proxies_iter);
	}
	g_assert_cmpint (g_hash_table_size (store), ==, 0);
}

void
nm_call_store_destroy (NMCallStore *store)
{
	g_return_if_fail (store);
	g_hash_table_destroy (store);
}
