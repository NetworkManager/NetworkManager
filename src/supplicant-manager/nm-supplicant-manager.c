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

#include "nm-default.h"

#include <string.h>

#include "nm-supplicant-manager.h"
#include "nm-supplicant-interface.h"
#include "nm-supplicant-types.h"
#include "nm-core-internal.h"

#define NM_SUPPLICANT_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                              NM_TYPE_SUPPLICANT_MANAGER, \
                                              NMSupplicantManagerPrivate))

G_DEFINE_TYPE (NMSupplicantManager, nm_supplicant_manager, G_TYPE_OBJECT)

#define _NMLOG_DOMAIN         LOGD_SUPPLICANT
#define _NMLOG_PREFIX_NAME    "supplicant"
#define _NMLOG(level, ...) \
    G_STMT_START { \
        nm_log ((level), _NMLOG_DOMAIN, \
                "%s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                _NMLOG_PREFIX_NAME": " \
                _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    } G_STMT_END

typedef struct {
	GDBusProxy *     proxy;
	GCancellable *   cancellable;
	gboolean         running;

	GSList          *ifaces;
	gboolean          fast_supported;
	NMSupplicantFeature ap_support;
	guint             die_count_reset_id;
	guint             die_count;
} NMSupplicantManagerPrivate;

/********************************************************************/

G_DEFINE_QUARK (nm-supplicant-error-quark, nm_supplicant_error);

/********************************************************************/

static inline gboolean
die_count_exceeded (guint32 count)
{
	return count > 2;
}

static gboolean
is_available (NMSupplicantManager *self)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	return    priv->running
	       && !die_count_exceeded (priv->die_count);
}

/********************************************************************/

static void
_sup_iface_last_ref (gpointer data,
                     GObject *object,
                     gboolean is_last_ref)
{
	NMSupplicantManager *self = data;
	NMSupplicantManagerPrivate *priv;
	NMSupplicantInterface *sup_iface = (NMSupplicantInterface *) object;
	const char *op;

	g_return_if_fail (NM_IS_SUPPLICANT_MANAGER (self));
	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (sup_iface));
	g_return_if_fail (is_last_ref);

	priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	if (!g_slist_find (priv->ifaces, sup_iface))
		g_return_if_reached ();

	/* Ask wpa_supplicant to remove this interface */
	if (   priv->running
	    && priv->proxy
	    && (op = nm_supplicant_interface_get_object_path (sup_iface))) {
		g_dbus_proxy_call (priv->proxy,
		                   "RemoveInterface",
		                   g_variant_new ("(o)", op),
		                   G_DBUS_CALL_FLAGS_NONE,
		                   3000,
		                   NULL,
		                   NULL,
		                   NULL);
	}

	priv->ifaces = g_slist_remove (priv->ifaces, sup_iface);
	g_object_remove_toggle_ref ((GObject *) sup_iface, _sup_iface_last_ref, self);
}

/**
 * nm_supplicant_manager_create_interface:
 * @self: the #NMSupplicantManager
 * @ifname: the interface for which to obtain the supplicant interface
 * @is_wireless: whether the interface is supposed to be wireless.
 *
 * Note: the manager owns a reference to the instance and the only way to
 *   get the manager to release it, is by dropping all other references
 *   to the supplicant-interface (or destroying the manager).
 *
 * Returns: (transfer full): returns a #NMSupplicantInterface or %NULL.
 *   Must be unrefed at the end.
 * */
NMSupplicantInterface *
nm_supplicant_manager_create_interface (NMSupplicantManager *self,
                                        const char *ifname,
                                        gboolean is_wireless)
{
	NMSupplicantManagerPrivate *priv;
	NMSupplicantInterface *iface;
	GSList *ifaces;

	g_return_val_if_fail (NM_IS_SUPPLICANT_MANAGER (self), NULL);
	g_return_val_if_fail (ifname != NULL, NULL);

	priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	_LOGD ("(%s): creating new supplicant interface", ifname);

	/* assert against not requesting duplicate interfaces. */
	for (ifaces = priv->ifaces; ifaces; ifaces = ifaces->next) {
		if (g_strcmp0 (nm_supplicant_interface_get_ifname (ifaces->data), ifname) == 0)
			g_return_val_if_reached (NULL);
	}

	iface = nm_supplicant_interface_new (ifname,
	                                     is_wireless,
	                                     priv->fast_supported,
	                                     priv->ap_support);

	priv->ifaces = g_slist_prepend (priv->ifaces, iface);
	g_object_add_toggle_ref ((GObject *) iface, _sup_iface_last_ref, self);

	/* If we're making the supplicant take a time out for a bit, don't
	 * let the supplicant interface start immediately, just let it hang
	 * around in INIT state until we're ready to talk to the supplicant
	 * again.
	 */
	if (is_available (self))
		nm_supplicant_interface_set_supplicant_available (iface, TRUE);

	return iface;
}

static void
update_capabilities (NMSupplicantManager *self)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	GSList *ifaces;
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
	priv->ap_support = NM_SUPPLICANT_FEATURE_UNKNOWN;

	value = g_dbus_proxy_get_cached_property (priv->proxy, "Capabilities");
	if (value) {
		if (g_variant_is_of_type (value, G_VARIANT_TYPE_STRING_ARRAY)) {
			array = g_variant_get_strv (value, NULL);
			priv->ap_support = NM_SUPPLICANT_FEATURE_NO;
			if (_nm_utils_string_in_list ("ap", array))
				priv->ap_support = NM_SUPPLICANT_FEATURE_YES;
			g_free (array);
		}
		g_variant_unref (value);
	}

	/* Tell all interfaces about results of the AP check */
	for (ifaces = priv->ifaces; ifaces; ifaces = ifaces->next)
		nm_supplicant_interface_set_ap_support (ifaces->data, priv->ap_support);

	_LOGD ("AP mode is %ssupported",
	       (priv->ap_support == NM_SUPPLICANT_FEATURE_YES) ? "" :
	           (priv->ap_support == NM_SUPPLICANT_FEATURE_NO) ? "not " : "possibly ");

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

	_LOGD ("EAP-FAST is %ssupported", priv->fast_supported ? "" : "not ");
}

static void
availability_changed (NMSupplicantManager *self, gboolean available)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	GSList *ifaces, *iter;

	if (!priv->ifaces)
		return;

	/* setting the supplicant as unavailable might cause the caller to unref
	 * the supplicant (and thus remove the instance from the list of interfaces.
	 * Delay that by taking an additional reference first. */
	ifaces = g_slist_copy (priv->ifaces);
	for (iter = ifaces; iter; iter = iter->next)
		g_object_ref (iter->data);
	for (iter = ifaces; iter; iter = iter->next)
		nm_supplicant_interface_set_supplicant_available (iter->data, available);
	g_slist_free_full (ifaces, g_object_unref);
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
	_LOGI ("wpa_supplicant die count reset");
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
	_LOGI ("wpa_supplicant %s", owner ? "running" : "stopped");

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
			_LOGI ("wpa_supplicant die count %d; ignoring for 10 seconds",
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
		_LOGW ("failed to acquire wpa_supplicant proxy: Wi-Fi and 802.1x will not be available (%s)",
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
	NMSupplicantManager *self = (NMSupplicantManager *) object;
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	GSList *ifaces;

	nm_clear_g_source (&priv->die_count_reset_id);

	if (priv->cancellable) {
		g_cancellable_cancel (priv->cancellable);
		g_clear_object (&priv->cancellable);
	}

	if (priv->ifaces) {
		for (ifaces = priv->ifaces; ifaces; ifaces = ifaces->next)
			g_object_remove_toggle_ref (ifaces->data, _sup_iface_last_ref, self);
		g_slist_free (priv->ifaces);
		priv->ifaces = NULL;
	}

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

