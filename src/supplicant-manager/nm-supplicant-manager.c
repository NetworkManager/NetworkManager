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
 * Copyright (C) 2006 - 2008 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include <string.h>
#include <glib.h>
#include <dbus/dbus.h>

#include "nm-supplicant-manager.h"
#include "nm-supplicant-interface.h"
#include "nm-dbus-manager.h"
#include "nm-marshal.h"
#include "nm-logging.h"
#include "nm-glib-compat.h"

#define SUPPLICANT_POKE_INTERVAL 120

typedef struct {
	NMDBusManager *	dbus_mgr;
	guint32         state;
	GSList *        ifaces;
	gboolean        dispose_has_run;
	guint			poke_id;
} NMSupplicantManagerPrivate;

#define NM_SUPPLICANT_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                              NM_TYPE_SUPPLICANT_MANAGER, \
                                              NMSupplicantManagerPrivate))

G_DEFINE_TYPE (NMSupplicantManager, nm_supplicant_manager, G_TYPE_OBJECT)


static void nm_supplicant_manager_name_owner_changed (NMDBusManager *dbus_mgr,
                                                      const char *name,
                                                      const char *old,
                                                      const char *new,
                                                      gpointer user_data);

static void nm_supplicant_manager_set_state (NMSupplicantManager * self,
                                             guint32 new_state);

static gboolean nm_supplicant_manager_startup (NMSupplicantManager * self);


/* Signals */
enum {
	STATE,       /* change in the manager's state */
	LAST_SIGNAL
};
static guint nm_supplicant_manager_signals[LAST_SIGNAL] = { 0 };


NMSupplicantManager *
nm_supplicant_manager_get (void)
{
	static NMSupplicantManager * singleton = NULL;

	if (!singleton) {
		singleton = NM_SUPPLICANT_MANAGER (g_object_new (NM_TYPE_SUPPLICANT_MANAGER, NULL));
	} else {
		g_object_ref (singleton);
	}

	g_assert (singleton);
	return singleton;
}

static gboolean
poke_supplicant_cb (gpointer user_data)
{
	NMSupplicantManager *self = NM_SUPPLICANT_MANAGER (user_data);
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	DBusGConnection *g_connection;
	DBusGProxy *proxy;
	const char *tmp = "ignoreme";

	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	proxy = dbus_g_proxy_new_for_name (g_connection,
	                                   WPAS_DBUS_SERVICE,
	                                   WPAS_DBUS_PATH,
	                                   WPAS_DBUS_INTERFACE);
	if (!proxy) {
		nm_log_warn (LOGD_SUPPLICANT, "Error: could not init wpa_supplicant proxy");
		goto out;
	}

	nm_log_info (LOGD_SUPPLICANT, "Trying to start the supplicant...");
	dbus_g_proxy_call_no_reply (proxy, "getInterface", G_TYPE_STRING, tmp, G_TYPE_INVALID);
	g_object_unref (proxy);

out:
	/* Reschedule the poke */	
	priv->poke_id = g_timeout_add_seconds (SUPPLICANT_POKE_INTERVAL,
	                               poke_supplicant_cb,
	                               (gpointer) self);

	return FALSE;
}

static void
nm_supplicant_manager_init (NMSupplicantManager * self)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	gboolean running;

	priv->dispose_has_run = FALSE;
	priv->state = NM_SUPPLICANT_MANAGER_STATE_DOWN;
	priv->dbus_mgr = nm_dbus_manager_get ();
	priv->poke_id = 0;

	running = nm_supplicant_manager_startup (self);

	g_signal_connect (priv->dbus_mgr,
	                  "name-owner-changed",
	                  G_CALLBACK (nm_supplicant_manager_name_owner_changed),
	                  self);

	if (!running) {
		/* Try to activate the supplicant */
		priv->poke_id = g_idle_add (poke_supplicant_cb, (gpointer) self);
	}
}

static void
nm_supplicant_manager_dispose (GObject *object)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (object);

	if (priv->dispose_has_run) {
		G_OBJECT_CLASS (nm_supplicant_manager_parent_class)->dispose (object);
		return;
	}

	priv->dispose_has_run = TRUE;

	if (priv->poke_id) {
		g_source_remove (priv->poke_id);
		priv->poke_id = 0;
	}

	if (priv->dbus_mgr) {
		g_object_unref (G_OBJECT (priv->dbus_mgr));
		priv->dbus_mgr = NULL;
	}

	/* Chain up to the parent class */
	G_OBJECT_CLASS (nm_supplicant_manager_parent_class)->dispose (object);
}

static void
nm_supplicant_manager_class_init (NMSupplicantManagerClass *klass)
{
	GObjectClass * object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMSupplicantManagerPrivate));

	object_class->dispose = nm_supplicant_manager_dispose;

	/* Signals */
	nm_supplicant_manager_signals[STATE] =
		g_signal_new ("state",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantManagerClass, state),
		              NULL, NULL,
		              _nm_marshal_VOID__UINT_UINT,
		              G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);
}

static void
nm_supplicant_manager_name_owner_changed (NMDBusManager *dbus_mgr,
                                          const char *name,
										  const char *old_owner,
										  const char *new_owner,
                                          gpointer user_data)
{
	NMSupplicantManager * self = (NMSupplicantManager *) user_data;
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	gboolean old_owner_good = (old_owner && strlen (old_owner));
	gboolean new_owner_good = (new_owner && strlen (new_owner));

	/* Can't handle the signal if its not from the supplicant service */
	if (strcmp (WPAS_DBUS_SERVICE, name) != 0)
		return;

	if (!old_owner_good && new_owner_good) {
		gboolean running;

		running = nm_supplicant_manager_startup (self);

		if (running && priv->poke_id) {
			g_source_remove (priv->poke_id);
			priv->poke_id = 0;
		}
	} else if (old_owner_good && !new_owner_good) {
		nm_supplicant_manager_set_state (self, NM_SUPPLICANT_MANAGER_STATE_DOWN);

		if (priv->poke_id)
			g_source_remove (priv->poke_id);

		/* Poke the supplicant so that it gets activated by dbus system bus
		 * activation.
		 */
		priv->poke_id = g_idle_add (poke_supplicant_cb, (gpointer) self);
	}
}


guint32
nm_supplicant_manager_get_state (NMSupplicantManager * self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_MANAGER (self), FALSE);

	return NM_SUPPLICANT_MANAGER_GET_PRIVATE (self)->state;
}

static void
nm_supplicant_manager_set_state (NMSupplicantManager * self, guint32 new_state)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	guint32 old_state;

	if (new_state == priv->state)
		return;

	old_state = priv->state;
	priv->state = new_state;
	g_signal_emit (self,
	               nm_supplicant_manager_signals[STATE],
	               0,
	               priv->state,
	               old_state);
}

static gboolean
nm_supplicant_manager_startup (NMSupplicantManager * self)
{
	gboolean running;

	/* FIXME: convert to pending call */
	running = nm_dbus_manager_name_has_owner (NM_SUPPLICANT_MANAGER_GET_PRIVATE (self)->dbus_mgr,
	                                          WPAS_DBUS_SERVICE);
	if (running)
		nm_supplicant_manager_set_state (self, NM_SUPPLICANT_MANAGER_STATE_IDLE);

	return running;
}

NMSupplicantInterface *
nm_supplicant_manager_get_iface (NMSupplicantManager * self,
								 const char *ifname,
								 gboolean is_wireless)
{
	NMSupplicantManagerPrivate *priv;
	NMSupplicantInterface * iface = NULL;
	GSList * elt;

	g_return_val_if_fail (NM_IS_SUPPLICANT_MANAGER (self), NULL);
	g_return_val_if_fail (ifname != NULL, NULL);

	priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	/* Ensure we don't already have this interface */
	for (elt = priv->ifaces; elt; elt = g_slist_next (elt)) {
		NMSupplicantInterface * if_tmp = (NMSupplicantInterface *) elt->data;

		if (!strcmp (ifname, nm_supplicant_interface_get_device (if_tmp))) {
			iface = if_tmp;
			break;
		}
	}

	if (!iface) {
		nm_log_dbg (LOGD_SUPPLICANT, "(%s): creating new supplicant interface", ifname);
		iface = nm_supplicant_interface_new (self, ifname, is_wireless);
		if (iface)
			priv->ifaces = g_slist_append (priv->ifaces, iface);
	} else {
		nm_log_dbg (LOGD_SUPPLICANT, "(%s): returning existing supplicant interface", ifname);
	}

	return iface;
}

void
nm_supplicant_manager_release_iface (NMSupplicantManager * self,
                                     NMSupplicantInterface * iface)
{
	NMSupplicantManagerPrivate *priv;
	GSList * elt;

	g_return_if_fail (NM_IS_SUPPLICANT_MANAGER (self));
	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (iface));

	priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	for (elt = priv->ifaces; elt; elt = g_slist_next (elt)) {
		NMSupplicantInterface * if_tmp = (NMSupplicantInterface *) elt->data;

		if (if_tmp == iface) {
			/* Remove the iface from the supplicant manager's list and
			 * dereference to match additional reference in get_iface.
			 */
			priv->ifaces = g_slist_remove_link (priv->ifaces, elt);
			g_slist_free_1 (elt);
			g_object_unref (iface);
			break;
		}
	}
}

const char *
nm_supplicant_manager_state_to_string (guint32 state)
{
	switch (state) {
	case NM_SUPPLICANT_MANAGER_STATE_DOWN:
		return "down";
	case NM_SUPPLICANT_MANAGER_STATE_IDLE:
		return "idle";
	default:
		break;
	}
	return "unknown";
}


