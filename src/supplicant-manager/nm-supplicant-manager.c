/*
 *  Copyright (C) 2006 Red Hat, Inc.
 *
 *  Written by Dan Williams <dcbw@redhat.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include <string.h>
#include <glib.h>
#include <dbus/dbus.h>

#include "nm-supplicant-manager.h"
#include "nm-supplicant-interface.h"
#include "nm-dbus-manager.h"
#include "nm-supplicant-marshal.h"
#include "nm-utils.h"

typedef struct {
	NMDBusManager *	dbus_mgr;
	guint32         state;
	GSList *        ifaces;
	gboolean        dispose_has_run;
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

static void nm_supplicant_manager_startup (NMSupplicantManager * self);


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

static void
poke_supplicant_cb  (DBusGProxy *proxy,
                     DBusGProxyCall *call_id,
                     gpointer user_data)
{
	/* Ignore the response, just trying to service-activate the supplicant */
}

static void
nm_supplicant_manager_init (NMSupplicantManager * self)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	NMDBusManager *dbus_mgr;
	DBusGConnection *g_connection;
	DBusGProxy *proxy;

	priv->dispose_has_run = FALSE;
	priv->state = NM_SUPPLICANT_MANAGER_STATE_DOWN;
	priv->dbus_mgr = nm_dbus_manager_get ();

	nm_supplicant_manager_startup (self);

	g_signal_connect (priv->dbus_mgr,
	                  "name-owner-changed",
	                  G_CALLBACK (nm_supplicant_manager_name_owner_changed),
	                  self);

	/* Poke the supplicant so that it gets activated by dbus system bus
	 * activation.
	 */
	dbus_mgr = nm_dbus_manager_get ();
	g_connection = nm_dbus_manager_get_connection (dbus_mgr);
	proxy = dbus_g_proxy_new_for_name (g_connection,
	                                   WPAS_DBUS_SERVICE,
	                                   WPAS_DBUS_PATH,
	                                   WPAS_DBUS_INTERFACE);
	if (!proxy) {
		nm_warning ("Error: could not init wpa_supplicant proxy");
	} else {
		DBusGProxyCall *call;
		const char *tmp = "ignore";

		call = dbus_g_proxy_begin_call (proxy, "getInterface",
		                                poke_supplicant_cb,
		                                NULL,
		                                NULL,
		                                G_TYPE_STRING, tmp,
		                                G_TYPE_INVALID);
	}
	g_object_unref (dbus_mgr);
}

static void
nm_supplicant_manager_dispose (GObject *object)
{
	NMSupplicantManagerPrivate *priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (object);

	if (priv->dispose_has_run) {
		/* If dispose did already run, return. */
		return;
	}

	/* Make sure dispose does not run twice. */
	priv->dispose_has_run = TRUE;

	/* 
	 * In dispose, you are supposed to free all types referenced from this
	 * object which might themselves hold a reference to self. Generally,
	 * the most simple solution is to unref all members on which you own a 
	 * reference.
	 */
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
		              nm_supplicant_marshal_VOID__UINT_UINT,
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
	gboolean old_owner_good = (old_owner && strlen (old_owner));
	gboolean new_owner_good = (new_owner && strlen (new_owner));

	/* Can't handle the signal if its not from the supplicant service */
	if (strcmp (WPAS_DBUS_SERVICE, name) != 0)
		return;

	if (!old_owner_good && new_owner_good) {
		nm_supplicant_manager_startup (self);
	} else if (old_owner_good && !new_owner_good) {
		nm_supplicant_manager_set_state (self, NM_SUPPLICANT_MANAGER_STATE_DOWN);
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

static void
nm_supplicant_manager_startup (NMSupplicantManager * self)
{
	gboolean running;

	/* FIXME: convert to pending call */
	running = nm_dbus_manager_name_has_owner (NM_SUPPLICANT_MANAGER_GET_PRIVATE (self)->dbus_mgr,
	                                          WPAS_DBUS_SERVICE);
	if (running) {
		nm_supplicant_manager_set_state (self, NM_SUPPLICANT_MANAGER_STATE_IDLE);
	}
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
		iface = nm_supplicant_interface_new (self, ifname, is_wireless);
		if (iface)
			priv->ifaces = g_slist_append (priv->ifaces, iface);
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
