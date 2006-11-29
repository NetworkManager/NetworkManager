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


#define NM_SUPPLICANT_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                              NM_TYPE_SUPPLICANT_MANAGER, \
                                              NMSupplicantManagerPrivate))

static void nm_supplicant_manager_name_owner_changed (NMDBusManager *dbus_mgr,
                                                      DBusConnection *connection,
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


struct _NMSupplicantManagerPrivate {
	NMDBusManager *	dbus_mgr;
	guint32         state;
	GSList *        ifaces;
	gboolean        dispose_has_run;
};


NMSupplicantManager *
nm_supplicant_manager_get (void)
{
	static NMSupplicantManager * singleton = NULL;
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;

	g_static_mutex_lock (&mutex);
	if (!singleton) {
		singleton = NM_SUPPLICANT_MANAGER (g_object_new (NM_TYPE_SUPPLICANT_MANAGER, NULL));
	} else {
		g_object_ref (singleton);
	}
	g_static_mutex_unlock (&mutex);

	g_assert (singleton);
	return singleton;
}


static void
nm_supplicant_manager_init (NMSupplicantManager * self)
{
	self->priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);

	self->priv->dispose_has_run = FALSE;
	self->priv->state = NM_SUPPLICANT_MANAGER_STATE_DOWN;
	self->priv->dbus_mgr = nm_dbus_manager_get (NULL);

	nm_supplicant_manager_startup (self);

	g_signal_connect (G_OBJECT (self->priv->dbus_mgr),
	                  "name-owner-changed",
	                  G_CALLBACK (nm_supplicant_manager_name_owner_changed),
	                  self);
}

static void
nm_supplicant_manager_dispose (GObject *object)
{
	NMSupplicantManager *      self = NM_SUPPLICANT_MANAGER (object);
	NMSupplicantManagerClass * klass;
	GObjectClass *             parent_class;  

	if (self->priv->dispose_has_run) {
		/* If dispose did already run, return. */
		return;
	}

	/* Make sure dispose does not run twice. */
	self->priv->dispose_has_run = TRUE;

	/* 
	 * In dispose, you are supposed to free all types referenced from this
	 * object which might themselves hold a reference to self. Generally,
	 * the most simple solution is to unref all members on which you own a 
	 * reference.
	 */
	if (self->priv->dbus_mgr) {
		g_object_unref (G_OBJECT (self->priv->dbus_mgr));
		self->priv->dbus_mgr = NULL;
	}

	/* Chain up to the parent class */
	klass = NM_SUPPLICANT_MANAGER_CLASS (g_type_class_peek (NM_TYPE_SUPPLICANT_MANAGER));
	parent_class = G_OBJECT_CLASS (g_type_class_peek_parent (klass));
	parent_class->dispose (object);
}

static void
nm_supplicant_manager_finalize (GObject *object)
{
	NMSupplicantManagerClass * klass;
	GObjectClass *             parent_class;  

	/* Chain up to the parent class */
	klass = NM_SUPPLICANT_MANAGER_CLASS (g_type_class_peek (NM_TYPE_SUPPLICANT_MANAGER));
	parent_class = G_OBJECT_CLASS (g_type_class_peek_parent (klass));
	parent_class->finalize (object);
}

static void
nm_supplicant_manager_class_init (NMSupplicantManagerClass *klass)
{
	GObjectClass * object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = nm_supplicant_manager_dispose;
	object_class->finalize = nm_supplicant_manager_finalize;

	g_type_class_add_private (object_class, sizeof (NMSupplicantManagerPrivate));

	/* Signals */
	nm_supplicant_manager_signals[STATE] =
		g_signal_new ("state",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantManagerClass, state),
		              NULL, NULL,
		              nm_supplicant_marshal_VOID__UINT_UINT,
		              G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);
	klass->state = NULL;
}

GType
nm_supplicant_manager_get_type (void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof (NMSupplicantManagerClass),
			NULL,	/* base_init */
			NULL,	/* base_finalize */
			(GClassInitFunc) nm_supplicant_manager_class_init,
			NULL,	/* class_finalize */
			NULL,	/* class_data */
			sizeof (NMSupplicantManager),
			0,		/* n_preallocs */
			(GInstanceInitFunc) nm_supplicant_manager_init,
			NULL		/* value_table */
		};

		type = g_type_register_static (G_TYPE_OBJECT,
								 "NMSupplicantManager",
								 &info, 0);
	}
	return type;
}

static void
nm_supplicant_manager_name_owner_changed (NMDBusManager *dbus_mgr,
                                          DBusConnection *connection,
                                          const char *name,
                                          const char *old,
                                          const char *new,
                                          gpointer user_data)
{
	NMSupplicantManager * self = (NMSupplicantManager *) user_data;
	gboolean		old_owner_good = (old && strlen (old));
	gboolean		new_owner_good = (new && strlen (new));

	g_return_if_fail (connection != NULL);

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
	g_return_val_if_fail (self != NULL, FALSE);

	return self->priv->state;
}

static void
nm_supplicant_manager_set_state (NMSupplicantManager * self, guint32 new_state)
{
	guint32 old_state;

	g_return_if_fail (self != NULL);
	g_return_if_fail (new_state < NM_SUPPLICANT_MANAGER_STATE_LAST);

	if (new_state == self->priv->state)
		return;

	old_state = self->priv->state;
	self->priv->state = new_state;
	g_signal_emit (G_OBJECT (self),
	               nm_supplicant_manager_signals[STATE],
	               0,
	               self->priv->state,
	               old_state);
}

static void
nm_supplicant_manager_startup (NMSupplicantManager * self)
{
	gboolean running;

	/* FIXME: convert to pending call */
	running = nm_dbus_manager_name_has_owner (self->priv->dbus_mgr,
	                                          WPAS_DBUS_SERVICE);
	if (running) {
		nm_supplicant_manager_set_state (self, NM_SUPPLICANT_MANAGER_STATE_IDLE);
	}
}

NMSupplicantInterface *
nm_supplicant_manager_get_iface (NMSupplicantManager * self,
                                 NMDevice * dev)
{
	NMSupplicantInterface * iface = NULL;
	GSList * elt;
	const char * ifname;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (dev != NULL, NULL);

	/* Ensure we don't already have this interface */
	ifname = nm_device_get_iface (dev);
	for (elt = self->priv->ifaces; elt; elt = g_slist_next (elt)) {
		NMSupplicantInterface * if_tmp = (NMSupplicantInterface *) elt->data;
		NMDevice * if_dev = nm_supplicant_interface_get_device (if_tmp);

		if (!strcmp (nm_device_get_iface (if_dev), ifname)) {
			iface = if_tmp;
			break;
		}
	}

	if (!iface) {
		iface = nm_supplicant_interface_new (self, dev);
		if (iface)
			self->priv->ifaces = g_slist_append (self->priv->ifaces, iface);
	}

	/* Object should have 2 references by now; one from the object's creation
	 * which is for the caller of this function, and one for the supplicant
	 * manager (because it's kept in the ifaces list) which is grabbed below.
	 */
	g_object_ref (iface);

	return iface;
}

void
nm_supplicant_manager_release_iface (NMSupplicantManager * self,
                                     NMSupplicantInterface * iface)
{
	GSList * elt;

	g_return_if_fail (self != NULL);
	g_return_if_fail (iface != NULL);

	for (elt = self->priv->ifaces; elt; elt = g_slist_next (elt)) {
		NMSupplicantInterface * if_tmp = (NMSupplicantInterface *) elt->data;

		if (if_tmp == iface) {
			/* Remove the iface from the supplicant manager's list and
			 * dereference to match additional reference in get_iface.
			 */
			self->priv->ifaces = g_slist_remove_link (self->priv->ifaces, elt);
			g_slist_free_1 (elt);
			g_object_unref (iface);
			break;
		}
	}

	/* One further dereference to match g_object_new() initial refcount of 1 */
	g_object_unref (iface);
}
