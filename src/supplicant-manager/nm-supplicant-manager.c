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
 * Copyright (C) 2006 - 2010 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "config.h"

#include <string.h>
#include <dbus/dbus.h>

#include "nm-default.h"
#include "nm-supplicant-manager.h"
#include "nm-supplicant-interface.h"
#include "nm-core-internal.h"

#define NM_SUPPLICANT_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                              NM_TYPE_SUPPLICANT_MANAGER, \
                                              NMSupplicantManagerPrivate))

G_DEFINE_TYPE (NMSupplicantManager, nm_supplicant_manager, G_TYPE_OBJECT)

typedef struct {
	GDBusProxy *     proxy;
	GCancellable *   cancellable;
	gboolean         running;

	GHashTable *    ifaces;
	gboolean        fast_supported;
	ApSupport       ap_support;
	guint           die_count_reset_id;
	guint           die_count;
} NMSupplicantManagerPrivate;

/********************************************************************/

static inline gboolean
die_count_exceeded (guint32 count)
{
	return count > 2;
}

NMSupplicantInterface *
nm_supplicant_manager_iface_get (NMSupplicantManager * self,
                                 const char *ifname,
                                 gboolean is_wireless)
{
	NMSupplicantManagerPrivate *priv;
	NMSupplicantInterface *iface = NULL;
	gboolean start_now;

	g_return_val_if_fail (NM_IS_SUPPLICANT_MANAGER (self), NULL);
	g_return_val_if_fail (ifname != NULL, NULL);

	priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	iface = g_hash_table_lookup (priv->ifaces, ifname);
	if (!iface) {
		/* If we're making the supplicant take a time out for a bit, don't
		 * let the supplicant interface start immediately, just let it hang
		 * around in INIT state until we're ready to talk to the supplicant
		 * again.
		 */
		start_now = !die_count_exceeded (priv->die_count);

		nm_log_dbg (LOGD_SUPPLICANT, "(%s): creating new supplicant interface", ifname);
		iface = nm_supplicant_interface_new (ifname,
		                                     is_wireless,
		                                     priv->fast_supported,
		                                     priv->ap_support,
		                                     start_now);
		if (iface) {
			g_hash_table_insert (priv->ifaces,
			                     (char *) nm_supplicant_interface_get_ifname (iface),
			                     iface);
		}
	} else {
		nm_log_dbg (LOGD_SUPPLICANT, "(%s): returning existing supplicant interface", ifname);
	}

	return iface;
}

void
nm_supplicant_manager_iface_release (NMSupplicantManager *self,
                                     NMSupplicantInterface *iface)
{
	NMSupplicantManagerPrivate *priv;
	const char *ifname, *op;

	g_return_if_fail (NM_IS_SUPPLICANT_MANAGER (self));
	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (iface));

	ifname = nm_supplicant_interface_get_ifname (iface);
	g_assert (ifname);

	priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (g_hash_table_lookup (priv->ifaces, ifname) == iface);

	/* Ask wpa_supplicant to remove this interface */
	op = nm_supplicant_interface_get_object_path (iface);
	if (priv->running && priv->proxy && op) {
		g_dbus_proxy_call (priv->proxy,
		                   "RemoveInterface",
		                   g_variant_new ("(o)", op),
		                   G_DBUS_CALL_FLAGS_NONE,
		                   3000,
		                   NULL,
		                   NULL,
		                   NULL);
	}

	g_hash_table_remove (priv->ifaces, ifname);
}

static void
update_capabilities (NMSupplicantManager *self)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	NMSupplicantInterface *iface;
	GHashTableIter hash_iter;
	const char **array;
	GVariant *value;

	/* The supplicant only advertises global capabilities if the following
	 * commit has been applied:
	 *
	 * commit 1634ac0654eba8d458640a115efc0a6cde3bac4d
	 * Author: Dan Williams <dcbw@redhat.com>
	 * Date:   Sat Sep 29 19:06:30 2012 +0300
	 *
	 * dbus: Add global capabilities property
	 */
	priv->ap_support = AP_SUPPORT_UNKNOWN;

	value = g_dbus_proxy_get_cached_property (priv->proxy, "Capabilities");
	if (value) {
		if (g_variant_is_of_type (value, G_VARIANT_TYPE_STRING_ARRAY)) {
			array = g_variant_get_strv (value, NULL);
			priv->ap_support = AP_SUPPORT_NO;
			if (_nm_utils_string_in_list ("ap", array))
				priv->ap_support = AP_SUPPORT_YES;
			g_free (array);
		}
		g_variant_unref (value);
	}

	/* Tell all interfaces about results of the AP check */
	g_hash_table_iter_init (&hash_iter, priv->ifaces);
	while (g_hash_table_iter_next (&hash_iter, NULL, (gpointer) &iface))
		nm_supplicant_interface_set_ap_support (iface, priv->ap_support);

	nm_log_dbg (LOGD_SUPPLICANT, "AP mode is %ssupported",
	            (priv->ap_support == AP_SUPPORT_YES) ? "" :
	                (priv->ap_support == AP_SUPPORT_NO) ? "not " : "possibly ");

	/* EAP-FAST */
	priv->fast_supported = FALSE;
	value = g_dbus_proxy_get_cached_property (priv->proxy, "EapMethods");
	if (value) {
		if (g_variant_is_of_type (value, G_VARIANT_TYPE_STRING_ARRAY)) {
			array = g_variant_get_strv (value, NULL);
			if (_nm_utils_string_in_list ("fast", array))
				priv->fast_supported = TRUE;
			g_free (array);
		}
		g_variant_unref (value);
	}

	nm_log_dbg (LOGD_SUPPLICANT, "EAP-FAST is %ssupported", priv->fast_supported ? "" : "not ");
}

static void
availability_changed (NMSupplicantManager *self, gboolean available)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	GList *ifaces, *iter;

	/* priv->ifaces may be modified if availability changes; can't use GHashTableIter */
	ifaces = g_hash_table_get_values (priv->ifaces);
	for (iter = ifaces; iter; iter = iter->next)
		nm_supplicant_interface_set_supplicant_available (NM_SUPPLICANT_INTERFACE (iter->data), available);
	g_list_free (ifaces);
}

static gboolean
is_available (NMSupplicantManager *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_MANAGER (self), FALSE);

	if (die_count_exceeded (NM_SUPPLICANT_MANAGER_GET_PRIVATE (self)->die_count))
		return FALSE;
	return NM_SUPPLICANT_MANAGER_GET_PRIVATE (self)->running;
}

static void
set_running (NMSupplicantManager *self, gboolean now_running)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	gboolean old_available = is_available (self);
	gboolean new_available;

	priv->running = now_running;
	new_available = is_available (self);
	if (old_available != new_available)
		availability_changed (self, new_available);
}

static void
set_die_count (NMSupplicantManager *self, guint new_die_count)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	gboolean old_available = is_available (self);
	gboolean new_available;

	priv->die_count = new_die_count;
	new_available = is_available (self);
	if (old_available != new_available)
		availability_changed (self, new_available);
}

static gboolean
wpas_die_count_reset_cb (gpointer user_data)
{
	NMSupplicantManager *self = NM_SUPPLICANT_MANAGER (user_data);
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	/* Reset the die count back to zero, which allows use of the supplicant again */
	priv->die_count_reset_id = 0;
	set_die_count (self, 0);
	nm_log_info (LOGD_SUPPLICANT, "wpa_supplicant die count reset");
	return FALSE;
}

static void
name_owner_cb (GDBusProxy *proxy, GParamSpec *pspec, gpointer user_data)
{
	NMSupplicantManager *self = NM_SUPPLICANT_MANAGER (user_data);
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	char *owner;

	g_return_if_fail (proxy == priv->proxy);

	owner = g_dbus_proxy_get_name_owner (proxy);
	nm_log_info (LOGD_SUPPLICANT, "wpa_supplicant %s", owner ? "running" : "stopped");

	if (owner) {
		set_running (self, TRUE);
		update_capabilities (self);
	} else if (priv->running) {
		/* Reschedule the die count reset timeout.  Every time the supplicant
		 * dies we wait 10 seconds before resetting the counter.  If the
		 * supplicant died more than twice before the timer is reset, then
		 * we don't try to talk to the supplicant for a while.
		 */
		if (priv->die_count_reset_id)
			g_source_remove (priv->die_count_reset_id);
		priv->die_count_reset_id = g_timeout_add_seconds (10, wpas_die_count_reset_cb, self);
		set_die_count (self, priv->die_count + 1);

		if (die_count_exceeded (priv->die_count)) {
			nm_log_info (LOGD_SUPPLICANT,
			             "wpa_supplicant die count %d; ignoring for 10 seconds",
			             priv->die_count);
		}

		set_running (self, FALSE);

		priv->fast_supported = FALSE;
	}

	g_free (owner);
}

static void
on_proxy_acquired (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantManager *self;
	NMSupplicantManagerPrivate *priv;
	GError *error = NULL;
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_new_for_bus_finish (result, &error);
	if (!proxy) {
		nm_log_warn (LOGD_SUPPLICANT,
		             "Failed to acquire wpa_supplicant proxy: Wi-Fi and 802.1x will not be available (%s)",
		             error->message);
		g_clear_error (&error);
		return;
	}

	self = NM_SUPPLICANT_MANAGER (user_data);
	priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	priv->proxy = proxy;
	g_signal_connect (priv->proxy, "notify::g-name-owner", G_CALLBACK (name_owner_cb), self);
	name_owner_cb (priv->proxy, NULL, self);
}

/*******************************************************************/

NM_DEFINE_SINGLETON_GETTER (NMSupplicantManager, nm_supplicant_manager_get, NM_TYPE_SUPPLICANT_MANAGER);

static void
nm_supplicant_manager_init (NMSupplicantManager *self)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	priv->ifaces = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);

	priv->cancellable = g_cancellable_new ();
	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                          G_DBUS_PROXY_FLAGS_NONE,
	                          NULL,
	                          WPAS_DBUS_SERVICE,
	                          WPAS_DBUS_PATH,
	                          WPAS_DBUS_INTERFACE,
	                          priv->cancellable,
	                          (GAsyncReadyCallback) on_proxy_acquired,
	                          self);
}

static void
dispose (GObject *object)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (object);

	if (priv->die_count_reset_id) {
		g_source_remove (priv->die_count_reset_id);
		priv->die_count_reset_id = 0;
	}

	if (priv->cancellable) {
		g_cancellable_cancel (priv->cancellable);
		g_clear_object (&priv->cancellable);
	}

	g_clear_pointer (&priv->ifaces, g_hash_table_unref);
	g_clear_object (&priv->proxy);

	G_OBJECT_CLASS (nm_supplicant_manager_parent_class)->dispose (object);
}

static void
nm_supplicant_manager_class_init (NMSupplicantManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMSupplicantManagerPrivate));

	object_class->dispose = dispose;
}

