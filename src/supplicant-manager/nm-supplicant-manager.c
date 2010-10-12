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

#define NM_SUPPLICANT_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                              NM_TYPE_SUPPLICANT_MANAGER, \
                                              NMSupplicantManagerPrivate))

G_DEFINE_TYPE (NMSupplicantManager, nm_supplicant_manager, G_TYPE_OBJECT)

/* Properties */
enum {
	PROP_0 = 0,
	PROP_RUNNING,
	LAST_PROP
};

typedef struct {
	NMDBusManager * dbus_mgr;
	guint           name_owner_id;
	DBusGProxy *    proxy;
	gboolean        running;
	GHashTable *    ifaces;
	gboolean        disposed;
} NMSupplicantManagerPrivate;

/********************************************************************/

NMSupplicantInterface *
nm_supplicant_manager_iface_get (NMSupplicantManager * self,
                                 const char *ifname,
                                 gboolean is_wireless)
{
	NMSupplicantManagerPrivate *priv;
	NMSupplicantInterface * iface = NULL;

	g_return_val_if_fail (NM_IS_SUPPLICANT_MANAGER (self), NULL);
	g_return_val_if_fail (ifname != NULL, NULL);

	priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	iface = g_hash_table_lookup (priv->ifaces, ifname);
	if (!iface) {
		nm_log_dbg (LOGD_SUPPLICANT, "(%s): creating new supplicant interface", ifname);
		iface = nm_supplicant_interface_new (self, ifname, is_wireless);
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
		dbus_g_proxy_call_no_reply (priv->proxy, "removeInterface", 
			                        DBUS_TYPE_G_OBJECT_PATH, op,
			                        G_TYPE_INVALID);
	}

	g_hash_table_remove (priv->ifaces, ifname);
}

gboolean
nm_supplicant_manager_running (NMSupplicantManager *self)
{
	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (NM_IS_SUPPLICANT_MANAGER (self), FALSE);

	return NM_SUPPLICANT_MANAGER_GET_PRIVATE (self)->running;
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
		priv->running = TRUE;
		g_object_notify (G_OBJECT (self), NM_SUPPLICANT_MANAGER_RUNNING);
	} else if (old_owner_good && !new_owner_good) {
		nm_log_info (LOGD_SUPPLICANT, "wpa_supplicant stopped");
		priv->running = FALSE;
		g_object_notify (G_OBJECT (self), NM_SUPPLICANT_MANAGER_RUNNING);
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
nm_supplicant_manager_init (NMSupplicantManager * self)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	DBusGConnection *bus;

	priv->dbus_mgr = nm_dbus_manager_get ();
	priv->name_owner_id = g_signal_connect (priv->dbus_mgr,
	                                        "name-owner-changed",
	                                        G_CALLBACK (name_owner_changed),
	                                        self);
	priv->running = nm_dbus_manager_name_has_owner (priv->dbus_mgr, WPAS_DBUS_SERVICE);

	bus = nm_dbus_manager_get_connection (priv->dbus_mgr);
	priv->proxy = dbus_g_proxy_new_for_name (bus,
	                                         WPAS_DBUS_SERVICE,
	                                         WPAS_DBUS_PATH,
	                                         WPAS_DBUS_INTERFACE);

	priv->ifaces = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
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
	case PROP_RUNNING:
		g_value_set_boolean (value, NM_SUPPLICANT_MANAGER_GET_PRIVATE (object)->running);
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

	if (priv->dbus_mgr) {
		if (priv->name_owner_id)
			g_signal_handler_disconnect (priv->dbus_mgr, priv->name_owner_id);
		g_object_unref (G_OBJECT (priv->dbus_mgr));
	}

	g_hash_table_destroy (priv->ifaces);

	if (priv->proxy)
		g_object_unref (priv->proxy);

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

	g_object_class_install_property (object_class, PROP_RUNNING,
		g_param_spec_boolean (NM_SUPPLICANT_MANAGER_RUNNING,
		                      "Running",
		                      "Running",
		                      FALSE,
		                      G_PARAM_READABLE));
}

