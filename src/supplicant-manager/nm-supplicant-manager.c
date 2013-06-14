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

#include <string.h>
#include <glib.h>
#include <dbus/dbus.h>

#include "nm-supplicant-manager.h"
#include "nm-supplicant-interface.h"
#include "nm-dbus-manager.h"
#include "nm-logging.h"
#include "nm-dbus-glib-types.h"

#define NM_SUPPLICANT_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                              NM_TYPE_SUPPLICANT_MANAGER, \
                                              NMSupplicantManagerPrivate))

G_DEFINE_TYPE (NMSupplicantManager, nm_supplicant_manager, G_TYPE_OBJECT)

/* Properties */
enum {
	PROP_0 = 0,
	PROP_AVAILABLE,
	LAST_PROP
};

typedef struct {
	NMDBusManager * dbus_mgr;
	guint           name_owner_id;
	DBusGProxy *    proxy;
	DBusGProxy *    props_proxy;
	gboolean        running;
	GHashTable *    ifaces;
	gboolean        fast_supported;
	ApSupport       ap_support;
	guint           die_count_reset_id;
	guint           die_count;
	gboolean        disposed;
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
		iface = nm_supplicant_interface_new (self,
		                                     ifname,
		                                     is_wireless,
		                                     priv->fast_supported,
		                                     priv->ap_support,
		                                     start_now);
		if (iface)
			g_hash_table_insert (priv->ifaces, g_strdup (ifname), iface);
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
		dbus_g_proxy_call_no_reply (priv->proxy, "RemoveInterface",
			                        DBUS_TYPE_G_OBJECT_PATH, op,
			                        G_TYPE_INVALID);
	}

	g_hash_table_remove (priv->ifaces, ifname);
}

static void
get_capabilities_cb  (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantManager *self = NM_SUPPLICANT_MANAGER (user_data);
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	NMSupplicantInterface *iface;
	GHashTableIter hash_iter;
	GError *error = NULL;
	GHashTable *props = NULL;
	GValue *value;
	char **iter;

	if (!dbus_g_proxy_end_call (proxy, call_id, &error,
	                            DBUS_TYPE_G_MAP_OF_VARIANT, &props,
	                            G_TYPE_INVALID)) {
		nm_log_warn (LOGD_CORE, "Unexpected error requesting supplicant properties: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		return;
	}

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
	value = g_hash_table_lookup (props, "Capabilities");
	if (value && G_VALUE_HOLDS (value, G_TYPE_STRV)) {
		priv->ap_support = AP_SUPPORT_NO;
		for (iter = g_value_get_boxed (value); iter && *iter; iter++) {
			if (strcasecmp (*iter, "ap") == 0)
				priv->ap_support = AP_SUPPORT_YES;
		}
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
	value = g_hash_table_lookup (props, "EapMethods");
	if (value && G_VALUE_HOLDS (value, G_TYPE_STRV)) {
		for (iter = g_value_get_boxed (value); iter && *iter; iter++) {
			if (strcasecmp (*iter, "fast") == 0)
				priv->fast_supported = TRUE;
		}
	}

	nm_log_dbg (LOGD_SUPPLICANT, "EAP-FAST is %ssupported", priv->fast_supported ? "" : "not ");

	g_hash_table_unref (props);
}

static void
check_capabilities (NMSupplicantManager *self)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	dbus_g_proxy_begin_call (priv->props_proxy, "GetAll",
	                         get_capabilities_cb, self, NULL,
	                         G_TYPE_STRING, WPAS_DBUS_INTERFACE,
	                         G_TYPE_INVALID);
}

gboolean
nm_supplicant_manager_available (NMSupplicantManager *self)
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
	gboolean old_available = nm_supplicant_manager_available (self);

	priv->running = now_running;
	if (old_available != nm_supplicant_manager_available (self))
		g_object_notify (G_OBJECT (self), NM_SUPPLICANT_MANAGER_AVAILABLE);
}

static void
set_die_count (NMSupplicantManager *self, guint new_die_count)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	gboolean old_available = nm_supplicant_manager_available (self);

	priv->die_count = new_die_count;
	if (old_available != nm_supplicant_manager_available (self))
		g_object_notify (G_OBJECT (self), NM_SUPPLICANT_MANAGER_AVAILABLE);
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
name_owner_changed (NMDBusManager *dbus_mgr,
                    const char *name,
                    const char *old_owner,
                    const char *new_owner,
                    gpointer user_data)
{
	NMSupplicantManager *self = NM_SUPPLICANT_MANAGER (user_data);
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	gboolean old_owner_good = (old_owner && strlen (old_owner));
	gboolean new_owner_good = (new_owner && strlen (new_owner));

	/* We only care about the supplicant here */
	if (strcmp (WPAS_DBUS_SERVICE, name) != 0)
		return;

	if (!old_owner_good && new_owner_good) {
		nm_log_info (LOGD_SUPPLICANT, "wpa_supplicant started");
		set_running (self, TRUE);
		check_capabilities (self);
	} else if (old_owner_good && !new_owner_good) {
		nm_log_info (LOGD_SUPPLICANT, "wpa_supplicant stopped");

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
}

/*******************************************************************/

NMSupplicantManager *
nm_supplicant_manager_get (void)
{
	static NMSupplicantManager *singleton = NULL;

	if (!singleton)
		singleton = NM_SUPPLICANT_MANAGER (g_object_new (NM_TYPE_SUPPLICANT_MANAGER, NULL));
	else
		g_object_ref (singleton);

	g_assert (singleton);
	return singleton;
}

static void
nm_supplicant_manager_init (NMSupplicantManager *self)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	DBusGConnection *bus;

	priv->dbus_mgr = nm_dbus_manager_get ();
	priv->name_owner_id = g_signal_connect (priv->dbus_mgr,
	                                        NM_DBUS_MANAGER_NAME_OWNER_CHANGED,
	                                        G_CALLBACK (name_owner_changed),
	                                        self);
	priv->running = nm_dbus_manager_name_has_owner (priv->dbus_mgr, WPAS_DBUS_SERVICE);

	bus = nm_dbus_manager_get_connection (priv->dbus_mgr);
	priv->proxy = dbus_g_proxy_new_for_name (bus,
	                                         WPAS_DBUS_SERVICE,
	                                         WPAS_DBUS_PATH,
	                                         WPAS_DBUS_INTERFACE);

	priv->props_proxy = dbus_g_proxy_new_for_name (bus,
	                                               WPAS_DBUS_SERVICE,
	                                               WPAS_DBUS_PATH,
	                                               DBUS_INTERFACE_PROPERTIES);

	priv->ifaces = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);

	/* Check generic supplicant capabilities */
	if (priv->running)
		check_capabilities (self);
}

static void
set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
}

static void
get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_AVAILABLE:
		g_value_set_boolean (value, nm_supplicant_manager_available (NM_SUPPLICANT_MANAGER (object)));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (object);

	if (priv->disposed)
		goto out;
	priv->disposed = TRUE;

	if (priv->die_count_reset_id)
		g_source_remove (priv->die_count_reset_id);

	if (priv->dbus_mgr) {
		if (priv->name_owner_id)
			g_signal_handler_disconnect (priv->dbus_mgr, priv->name_owner_id);
		priv->dbus_mgr = NULL;
	}

	g_hash_table_destroy (priv->ifaces);

	if (priv->proxy)
		g_object_unref (priv->proxy);

	if (priv->props_proxy)
		g_object_unref (priv->props_proxy);

out:
	/* Chain up to the parent class */
	G_OBJECT_CLASS (nm_supplicant_manager_parent_class)->dispose (object);
}

static void
nm_supplicant_manager_class_init (NMSupplicantManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMSupplicantManagerPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;

	g_object_class_install_property (object_class, PROP_AVAILABLE,
		g_param_spec_boolean (NM_SUPPLICANT_MANAGER_AVAILABLE,
		                      "Available",
		                      "Available",
		                      FALSE,
		                      G_PARAM_READABLE));
}

