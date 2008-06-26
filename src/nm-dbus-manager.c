/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include "config.h"
#include "NetworkManager.h"
#include "nm-dbus-manager.h"
#include "nm-marshal.h"

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <string.h>
#include "nm-utils.h"

enum {
	DBUS_CONNECTION_CHANGED = 0,
	NAME_OWNER_CHANGED,
	NUMBER_OF_SIGNALS
};

static guint nm_dbus_manager_signals[NUMBER_OF_SIGNALS];

G_DEFINE_TYPE(NMDBusManager, nm_dbus_manager, G_TYPE_OBJECT)

#define NM_DBUS_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
													    NM_TYPE_DBUS_MANAGER, \
													    NMDBusManagerPrivate))

typedef struct {
	DBusConnection * connection;
	DBusGConnection *g_connection;
	DBusGProxy *     proxy;
	gboolean         started;
} NMDBusManagerPrivate;

static gboolean nm_dbus_manager_init_bus (NMDBusManager *self);
static void nm_dbus_manager_cleanup (NMDBusManager *self);
static void start_reconnection_timeout (NMDBusManager *self);

NMDBusManager *
nm_dbus_manager_get (void)
{
	static NMDBusManager *singleton = NULL;

	if (!singleton) {
		singleton = NM_DBUS_MANAGER (g_object_new (NM_TYPE_DBUS_MANAGER, NULL));
		if (!nm_dbus_manager_init_bus (singleton))
			start_reconnection_timeout (singleton);
	} else {
		g_object_ref (singleton);
	}

	g_assert (singleton);
	return singleton;
}

static void
nm_dbus_manager_init (NMDBusManager *self)
{
}

static void
nm_dbus_manager_finalize (GObject *object)
{
	nm_dbus_manager_cleanup (NM_DBUS_MANAGER (object));

	G_OBJECT_CLASS (nm_dbus_manager_parent_class)->finalize (object);
}

static void
nm_dbus_manager_class_init (NMDBusManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = nm_dbus_manager_finalize;

	nm_dbus_manager_signals[DBUS_CONNECTION_CHANGED] =
		g_signal_new ("dbus-connection-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMDBusManagerClass, dbus_connection_changed),
		              NULL, NULL, nm_marshal_VOID__POINTER,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);

	nm_dbus_manager_signals[NAME_OWNER_CHANGED] =
		g_signal_new ("name-owner-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMDBusManagerClass, name_owner_changed),
		              NULL, NULL, nm_marshal_VOID__STRING_STRING_STRING,
		              G_TYPE_NONE, 3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

	g_type_class_add_private (klass, sizeof (NMDBusManagerPrivate));
}


/* Only cleanup a specific dbus connection, not all our private data */
static void
nm_dbus_manager_cleanup (NMDBusManager *self)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	if (priv->proxy) {
		g_object_unref (priv->proxy);
		priv->proxy = NULL;
	}

	if (priv->g_connection) {
		dbus_g_connection_unref (priv->g_connection);
		priv->g_connection = NULL;
		priv->connection = NULL;
	}

	priv->started = FALSE;
}

static gboolean
nm_dbus_manager_reconnect (gpointer user_data)
{
	NMDBusManager *self = NM_DBUS_MANAGER (user_data);

	g_assert (self != NULL);

	if (nm_dbus_manager_init_bus (self)) {
		if (nm_dbus_manager_start_service (self)) {
			nm_info ("reconnected to the system bus.");
			g_signal_emit (self,
						nm_dbus_manager_signals[DBUS_CONNECTION_CHANGED],
						0,
						NM_DBUS_MANAGER_GET_PRIVATE (self)->connection);
			return TRUE;
		}
	}

	nm_dbus_manager_cleanup (self);
	return FALSE;
}

static void
start_reconnection_timeout (NMDBusManager *self)
{
	/* Schedule timeout for reconnection attempts */
	g_timeout_add (3000, nm_dbus_manager_reconnect, self);
}

char *
nm_dbus_manager_get_name_owner (NMDBusManager *self,
                                const char *name)
{
	char *owner = NULL;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_DBUS_MANAGER (self), NULL);
	g_return_val_if_fail (name != NULL, NULL);

	if (!dbus_g_proxy_call (NM_DBUS_MANAGER_GET_PRIVATE (self)->proxy,
					    "GetNameOwner", &err,
					    G_TYPE_STRING, name,
					    G_TYPE_INVALID,
					    G_TYPE_STRING, &owner,
					    G_TYPE_INVALID)) {
		nm_warning ("Error on GetNameOwner DBUS call: %s", err->message);
		g_error_free (err);
	}

	return owner;
}

gboolean
nm_dbus_manager_name_has_owner (NMDBusManager *self,
                                const char *name)
{
	gboolean has_owner = FALSE;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_DBUS_MANAGER (self), FALSE);
	g_return_val_if_fail (name != NULL, FALSE);

	if (!dbus_g_proxy_call (NM_DBUS_MANAGER_GET_PRIVATE (self)->proxy,
					    "NameHasOwner", &err,
					    G_TYPE_STRING, name,
					    G_TYPE_INVALID,
					    G_TYPE_BOOLEAN, &has_owner,
					    G_TYPE_INVALID)) {
		nm_warning ("Error on NameHasOwner DBUS call: %s", err->message);
		g_error_free (err);
	}

	return has_owner;
}

static void
proxy_name_owner_changed (DBusGProxy *proxy,
					 const char *name,
					 const char *old_owner,
					 const char *new_owner,
					 gpointer user_data)
{
	g_signal_emit (NM_DBUS_MANAGER (user_data),
				nm_dbus_manager_signals[NAME_OWNER_CHANGED],
				0,
				name, old_owner, new_owner);
}

static void
destroy_cb (DBusGProxy *proxy, gpointer user_data)
{
	NMDBusManager *self = NM_DBUS_MANAGER (user_data);

	/* Clean up existing connection */
	nm_info ("disconnected by the system bus.");
	NM_DBUS_MANAGER_GET_PRIVATE (self)->proxy = NULL;

	nm_dbus_manager_cleanup (self);

	g_signal_emit (G_OBJECT (self), 
				nm_dbus_manager_signals[DBUS_CONNECTION_CHANGED],
				0, NULL);

	start_reconnection_timeout (self);
}

static gboolean
nm_dbus_manager_init_bus (NMDBusManager *self)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	GError *err = NULL;

	if (priv->connection) {
		nm_warning ("DBus Manager already has a valid connection.");
		return FALSE;
	}

	dbus_connection_set_change_sigpipe (TRUE);

	priv->g_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!priv->g_connection) {
		nm_warning ("Could not get the system bus.  Make sure "
		            "the message bus daemon is running!  Message: %s",
		            err->message);
		g_error_free (err);
		return FALSE;
	}

	priv->connection = dbus_g_connection_get_connection (priv->g_connection);
	dbus_connection_set_exit_on_disconnect (priv->connection, FALSE);

	priv->proxy = dbus_g_proxy_new_for_name (priv->g_connection,
									 "org.freedesktop.DBus",
									 "/org/freedesktop/DBus",
									 "org.freedesktop.DBus");

	g_signal_connect (priv->proxy, "destroy",
				   G_CALLBACK (destroy_cb),
				   self);

	dbus_g_proxy_add_signal (priv->proxy, "NameOwnerChanged",
						G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
						G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy,
						    "NameOwnerChanged",
						    G_CALLBACK (proxy_name_owner_changed),
						    self, NULL);
	return TRUE;
}

/* Register our service on the bus; shouldn't be called until
 * all necessary message handlers have been registered, because
 * when we register on the bus, clients may start to call.
 */
gboolean
nm_dbus_manager_start_service (NMDBusManager *self)
{
	NMDBusManagerPrivate *priv;
	int flags;
	int request_name_result;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_DBUS_MANAGER (self), FALSE);

	priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	if (priv->started) {
		nm_warning ("Service has already started.");
		return FALSE;
	}

#if (DBUS_VERSION_MAJOR == 0) && (DBUS_VERSION_MINOR < 60)
	flags = DBUS_NAME_FLAG_PROHIBIT_REPLACEMENT;
#else
	flags = DBUS_NAME_FLAG_DO_NOT_QUEUE;
#endif

	if (!dbus_g_proxy_call (priv->proxy, "RequestName", &err,
					    G_TYPE_STRING, NM_DBUS_SERVICE,
					    G_TYPE_UINT, flags,
					    G_TYPE_INVALID,
					    G_TYPE_UINT, &request_name_result,
					    G_TYPE_INVALID)) {
		nm_warning ("Could not acquire the NetworkManager service.\n"
		            "  Message: '%s'", err->message);
		g_error_free (err);
		goto out;
	}

	if (request_name_result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		nm_warning ("Could not acquire the NetworkManager service as it is already taken.");
		goto out;
	}

	priv->started = TRUE;

 out:
	if (!priv->started)
		nm_dbus_manager_cleanup (self);

	return priv->started;
}

DBusConnection *
nm_dbus_manager_get_dbus_connection (NMDBusManager *self)
{
	g_return_val_if_fail (NM_IS_DBUS_MANAGER (self), NULL);

	return NM_DBUS_MANAGER_GET_PRIVATE (self)->connection;
}

DBusGConnection *
nm_dbus_manager_get_connection (NMDBusManager *self)
{
	g_return_val_if_fail (NM_IS_DBUS_MANAGER (self), NULL);

	return NM_DBUS_MANAGER_GET_PRIVATE (self)->g_connection;
}
