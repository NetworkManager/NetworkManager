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

#include "nm-supplicant-manager.h"

#include "nm-supplicant-interface.h"
#include "nm-supplicant-types.h"
#include "nm-core-internal.h"

/*****************************************************************************/

typedef struct {
	GDBusProxy *     proxy;
	GCancellable *   cancellable;
	gboolean         running;

	GSList          *ifaces;
	NMSupplicantFeature fast_support;
	NMSupplicantFeature ap_support;
	NMSupplicantFeature pmf_support;
	NMSupplicantFeature fils_support;
	NMSupplicantFeature p2p_support;
	NMSupplicantFeature wfd_support;
	guint             die_count_reset_id;
	guint             die_count;
} NMSupplicantManagerPrivate;

struct _NMSupplicantManager {
	GObject parent;
	NMSupplicantManagerPrivate _priv;
};

struct _NMSupplicantManagerClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMSupplicantManager, nm_supplicant_manager, G_TYPE_OBJECT)

#define NM_SUPPLICANT_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMSupplicantManager, NM_IS_SUPPLICANT_MANAGER)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_SUPPLICANT
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "supplicant", __VA_ARGS__)

/*****************************************************************************/

NM_CACHED_QUARK_FCN ("nm-supplicant-error-quark", nm_supplicant_error_quark)

/*****************************************************************************/

static gboolean
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

/*****************************************************************************/

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

static void
on_supplicant_wfd_ies_set (GObject *source_object,
                           GAsyncResult *res,
                           gpointer user_data)
{
	gs_unref_variant GVariant *result = NULL;
	gs_free_error GError *error = NULL;

	result = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source_object), res, &error);

	if (!result)
		_LOGW ("failed to set WFD IEs on wpa_supplicant: %s", error->message);
}

/**
 * nm_supplicant_manager_set_wfd_ies:
 * @self: the #NMSupplicantManager
 * @wfd_ies: a #GBytes with the WFD IEs or %NULL
 *
 * This function sets the global WFD IEs on wpa_supplicant. Note that
 * it would make more sense if this was per-device, but wpa_supplicant
 * simply does not work that way.
 * */
void
nm_supplicant_manager_set_wfd_ies (NMSupplicantManager *self,
                                   GBytes *wfd_ies)
{
	NMSupplicantManagerPrivate *priv;
	GVariantBuilder params;
	GVariant *val;

	g_return_if_fail (NM_IS_SUPPLICANT_MANAGER (self));

	priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	_LOGD ("setting WFD IEs for P2P operation");

	if (wfd_ies)
		val = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                 g_bytes_get_data (wfd_ies, NULL),
		                                 g_bytes_get_size (wfd_ies),
		                                 sizeof (guint8));
	else
		val = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                 NULL, 0, sizeof (guint8));

	g_variant_builder_init (&params, G_VARIANT_TYPE ("(ssv)"));

	g_variant_builder_add (&params, "s", g_dbus_proxy_get_interface_name (priv->proxy));
	g_variant_builder_add (&params, "s", "WFDIEs");
	g_variant_builder_add_value (&params, g_variant_new_variant (val));

	g_dbus_connection_call (g_dbus_proxy_get_connection (priv->proxy),
	                        g_dbus_proxy_get_name (priv->proxy),
	                        g_dbus_proxy_get_object_path (priv->proxy),
	                        "org.freedesktop.DBus.Properties",
	                        "Set",
	                        g_variant_builder_end (&params),
	                        G_VARIANT_TYPE_UNIT,
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                        1000,
	                        NULL,
	                        on_supplicant_wfd_ies_set,
	                        NULL);
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
                                        NMSupplicantDriver driver)
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
	                                     NULL,
	                                     driver,
	                                     priv->fast_support,
	                                     priv->ap_support,
	                                     priv->pmf_support,
	                                     priv->fils_support,
	                                     priv->p2p_support,
	                                     priv->wfd_support);

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

/**
 * nm_supplicant_manager_create_interface_from_path:
 * @self: the #NMSupplicantManager
 * @object_path: the DBus object path for which to obtain the supplicant interface
 *
 * Note: the manager owns a reference to the instance and the only way to
 *   get the manager to release it, is by dropping all other references
 *   to the supplicant-interface (or destroying the manager).
 *
 * Returns: (transfer full): returns a #NMSupplicantInterface or %NULL.
 *   Must be unrefed at the end.
 * */
NMSupplicantInterface *
nm_supplicant_manager_create_interface_from_path (NMSupplicantManager *self,
                                                  const char *object_path)
{
	NMSupplicantManagerPrivate *priv;
	NMSupplicantInterface *iface;
	GSList *ifaces;

	g_return_val_if_fail (NM_IS_SUPPLICANT_MANAGER (self), NULL);
	g_return_val_if_fail (object_path != NULL, NULL);

	priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	_LOGD ("creating new supplicant interface for dbus path %s", object_path);

	/* assert against not requesting duplicate interfaces. */
	for (ifaces = priv->ifaces; ifaces; ifaces = ifaces->next) {
		if (g_strcmp0 (nm_supplicant_interface_get_object_path (ifaces->data), object_path) == 0)
			g_return_val_if_reached (NULL);
	}

	iface = nm_supplicant_interface_new (NULL,
	                                     object_path,
	                                     NM_SUPPLICANT_DRIVER_WIRELESS,
	                                     priv->fast_support,
	                                     priv->ap_support,
	                                     priv->pmf_support,
	                                     priv->fils_support,
	                                     priv->p2p_support,
	                                     priv->wfd_support);

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
	priv->pmf_support = NM_SUPPLICANT_FEATURE_UNKNOWN;
	priv->fils_support = NM_SUPPLICANT_FEATURE_UNKNOWN;
	/* P2P support is newer than the capabilities property */
	priv->p2p_support = NM_SUPPLICANT_FEATURE_NO;

	value = g_dbus_proxy_get_cached_property (priv->proxy, "Capabilities");
	if (value) {
		if (g_variant_is_of_type (value, G_VARIANT_TYPE_STRING_ARRAY)) {
			array = g_variant_get_strv (value, NULL);
			priv->ap_support = NM_SUPPLICANT_FEATURE_NO;
			priv->pmf_support = NM_SUPPLICANT_FEATURE_NO;
			priv->fils_support = NM_SUPPLICANT_FEATURE_NO;
			priv->p2p_support = NM_SUPPLICANT_FEATURE_NO;
			if (array) {
				if (g_strv_contains (array, "ap"))
					priv->ap_support = NM_SUPPLICANT_FEATURE_YES;
				if (g_strv_contains (array, "pmf"))
					priv->pmf_support = NM_SUPPLICANT_FEATURE_YES;
				if (g_strv_contains (array, "fils"))
					priv->fils_support = NM_SUPPLICANT_FEATURE_YES;
				if (g_strv_contains (array, "p2p"))
					priv->p2p_support = NM_SUPPLICANT_FEATURE_YES;
				g_free (array);
			}
		}
		g_variant_unref (value);
	}

	/* Tell all interfaces about results of the AP/PMF/FILS/P2P check */
	for (ifaces = priv->ifaces; ifaces; ifaces = ifaces->next) {
		nm_supplicant_interface_set_ap_support (ifaces->data, priv->ap_support);
		nm_supplicant_interface_set_pmf_support (ifaces->data, priv->pmf_support);
		nm_supplicant_interface_set_fils_support (ifaces->data, priv->fils_support);
		nm_supplicant_interface_set_p2p_support (ifaces->data, priv->p2p_support);
	}

	_LOGD ("AP mode is %ssupported",
	       (priv->ap_support == NM_SUPPLICANT_FEATURE_YES) ? "" :
	           (priv->ap_support == NM_SUPPLICANT_FEATURE_NO) ? "not " : "possibly ");
	_LOGD ("PMF is %ssupported",
	       (priv->pmf_support == NM_SUPPLICANT_FEATURE_YES) ? "" :
	           (priv->pmf_support == NM_SUPPLICANT_FEATURE_NO) ? "not " : "possibly ");
	_LOGD ("FILS is %ssupported",
	       (priv->fils_support == NM_SUPPLICANT_FEATURE_YES) ? "" :
	           (priv->fils_support == NM_SUPPLICANT_FEATURE_NO) ? "not " : "possibly ");
	_LOGD ("P2P is %ssupported",
	       (priv->p2p_support == NM_SUPPLICANT_FEATURE_YES) ? "" :
	           (priv->p2p_support == NM_SUPPLICANT_FEATURE_NO) ? "not " : "possibly ");

	/* EAP-FAST */
	priv->fast_support = NM_SUPPLICANT_FEATURE_NO;
	value = g_dbus_proxy_get_cached_property (priv->proxy, "EapMethods");
	if (value) {
		if (g_variant_is_of_type (value, G_VARIANT_TYPE_STRING_ARRAY)) {
			array = g_variant_get_strv (value, NULL);
			if (array) {
				const char **a;

				for (a = array; *a; a++) {
					if (g_ascii_strcasecmp (*a, "FAST") == 0) {
						priv->fast_support = NM_SUPPLICANT_FEATURE_YES;
						break;
					}
				}
				g_free (array);
			}
		}
		g_variant_unref (value);
	}

	for (ifaces = priv->ifaces; ifaces; ifaces = ifaces->next)
		nm_supplicant_interface_set_fast_support (ifaces->data, priv->fast_support);

	_LOGD ("EAP-FAST is %ssupported",
	       (priv->fast_support == NM_SUPPLICANT_FEATURE_YES) ? "" :
	           (priv->fast_support == NM_SUPPLICANT_FEATURE_NO) ? "not " : "possibly ");

	priv->wfd_support = NM_SUPPLICANT_FEATURE_NO;
	value = g_dbus_proxy_get_cached_property (priv->proxy, "WFDIEs");
	if (value) {
		priv->wfd_support = NM_SUPPLICANT_FEATURE_YES;
		g_variant_unref (value);
	}

	for (ifaces = priv->ifaces; ifaces; ifaces = ifaces->next)
		nm_supplicant_interface_set_wfd_support (ifaces->data, priv->fast_support);

	_LOGD ("WFD is %ssupported",
	       (priv->wfd_support == NM_SUPPLICANT_FEATURE_YES) ? "" :
	           (priv->wfd_support == NM_SUPPLICANT_FEATURE_NO) ? "not " : "possibly ");
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
		update_capabilities (self);
		set_running (self, TRUE);
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

		priv->ap_support = NM_SUPPLICANT_FEATURE_UNKNOWN;
		priv->fast_support = NM_SUPPLICANT_FEATURE_UNKNOWN;
		priv->pmf_support = NM_SUPPLICANT_FEATURE_UNKNOWN;
		priv->fils_support = NM_SUPPLICANT_FEATURE_UNKNOWN;

		set_running (self, FALSE);
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

/*****************************************************************************/

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

	nm_clear_g_cancellable (&priv->cancellable);

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

	object_class->dispose = dispose;
}

