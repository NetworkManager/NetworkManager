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
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "config.h"
#include "NetworkManager.h"
#include "nm-dbus-manager.h"
#include "nm-marshal.h"
#include "nm-glib-compat.h"

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <string.h>
#include "nm-logging.h"

enum {
	DBUS_CONNECTION_CHANGED = 0,
	NAME_OWNER_CHANGED,
	NUMBER_OF_SIGNALS
};

static guint signals[NUMBER_OF_SIGNALS];

G_DEFINE_TYPE(NMDBusManager, nm_dbus_manager, G_TYPE_OBJECT)

#define NM_DBUS_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                        NM_TYPE_DBUS_MANAGER, \
                                        NMDBusManagerPrivate))

typedef struct {
	DBusConnection *connection;
	DBusGConnection *g_connection;
	gboolean started;

	DBusGProxy *proxy;
	guint proxy_destroy_id;

	guint reconnect_id;
} NMDBusManagerPrivate;

static gboolean nm_dbus_manager_init_bus (NMDBusManager *self);
static void nm_dbus_manager_cleanup (NMDBusManager *self, gboolean dispose);
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
nm_dbus_manager_dispose (GObject *object)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (object);

	nm_dbus_manager_cleanup (NM_DBUS_MANAGER (object), TRUE);

	if (priv->reconnect_id) {
		g_source_remove (priv->reconnect_id);
		priv->reconnect_id = 0;
	}

	G_OBJECT_CLASS (nm_dbus_manager_parent_class)->dispose (object);
}

static void
nm_dbus_manager_class_init (NMDBusManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = nm_dbus_manager_dispose;

	signals[DBUS_CONNECTION_CHANGED] =
		g_signal_new ("dbus-connection-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMDBusManagerClass, dbus_connection_changed),
		              NULL, NULL, _nm_marshal_VOID__POINTER,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);

	signals[NAME_OWNER_CHANGED] =
		g_signal_new ("name-owner-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMDBusManagerClass, name_owner_changed),
		              NULL, NULL, _nm_marshal_VOID__STRING_STRING_STRING,
		              G_TYPE_NONE, 3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

	g_type_class_add_private (klass, sizeof (NMDBusManagerPrivate));
}


/* Only cleanup a specific dbus connection, not all our private data */
static void
nm_dbus_manager_cleanup (NMDBusManager *self, gboolean dispose)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	if (priv->proxy) {
		if (dispose) {
			g_signal_handler_disconnect (priv->proxy, priv->proxy_destroy_id);
			priv->proxy_destroy_id = 0;
		}
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
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	g_assert (self != NULL);

	if (nm_dbus_manager_init_bus (self)) {
		if (nm_dbus_manager_start_service (self)) {
			nm_log_info (LOGD_CORE, "reconnected to the system bus.");
			g_signal_emit (self, signals[DBUS_CONNECTION_CHANGED],
			               0, priv->connection);
			priv->reconnect_id = 0;
			return FALSE;
		}
	}

	/* Try again */
	nm_dbus_manager_cleanup (self, FALSE);
	return TRUE;
}

static void
start_reconnection_timeout (NMDBusManager *self)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	if (priv->reconnect_id)
		g_source_remove (priv->reconnect_id);

	/* Schedule timeout for reconnection attempts */
	priv->reconnect_id = g_timeout_add_seconds (3, nm_dbus_manager_reconnect, self);
}

char *
nm_dbus_manager_get_name_owner (NMDBusManager *self,
                                const char *name,
                                GError **error)
{
	char *owner = NULL;

	g_return_val_if_fail (NM_IS_DBUS_MANAGER (self), NULL);
	g_return_val_if_fail (name != NULL, NULL);
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	if (!dbus_g_proxy_call_with_timeout (NM_DBUS_MANAGER_GET_PRIVATE (self)->proxy,
	                                     "GetNameOwner", 2000, error,
	                                     G_TYPE_STRING, name,
	                                     G_TYPE_INVALID,
	                                     G_TYPE_STRING, &owner,
	                                     G_TYPE_INVALID)) {
		return NULL;
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
		nm_log_warn (LOGD_CORE, "NameHasOwner request failed: %s",
		             (err && err->message) ? err->message : "(unknown)");
		g_clear_error (&err);
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
	g_signal_emit (G_OBJECT (user_data), signals[NAME_OWNER_CHANGED],
	               0, name, old_owner, new_owner);
}

static void
destroy_cb (DBusGProxy *proxy, gpointer user_data)
{
	NMDBusManager *self = NM_DBUS_MANAGER (user_data);

	/* Clean up existing connection */
	nm_log_warn (LOGD_CORE, "disconnected by the system bus.");
	NM_DBUS_MANAGER_GET_PRIVATE (self)->proxy = NULL;

	nm_dbus_manager_cleanup (self, FALSE);

	g_signal_emit (G_OBJECT (self), signals[DBUS_CONNECTION_CHANGED], 0, NULL);

	start_reconnection_timeout (self);
}

static gboolean
nm_dbus_manager_init_bus (NMDBusManager *self)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	GError *err = NULL;

	if (priv->connection) {
		nm_log_warn (LOGD_CORE, "DBus Manager already has a valid connection.");
		return FALSE;
	}

	dbus_connection_set_change_sigpipe (TRUE);

	priv->g_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!priv->g_connection) {
		nm_log_err (LOGD_CORE, "Could not get the system bus.  Make sure "
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

	priv->proxy_destroy_id = g_signal_connect (priv->proxy, "destroy",
	                                           G_CALLBACK (destroy_cb), self);

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
	int result;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_DBUS_MANAGER (self), FALSE);

	priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	if (priv->started) {
		nm_log_err (LOGD_CORE, "Service has already started.");
		return FALSE;
	}

	if (!dbus_g_proxy_call (priv->proxy, "RequestName", &err,
	                        G_TYPE_STRING, NM_DBUS_SERVICE,
	                        G_TYPE_UINT, DBUS_NAME_FLAG_DO_NOT_QUEUE,
	                        G_TYPE_INVALID,
	                        G_TYPE_UINT, &result,
	                        G_TYPE_INVALID)) {
		nm_log_err (LOGD_CORE, "Could not acquire the NetworkManager service.\n"
		            "  Error: '%s'",
		            (err && err->message) ? err->message : "(unknown)");
		g_error_free (err);
		return FALSE;
	}

	if (result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		nm_log_err (LOGD_CORE, "Could not acquire the NetworkManager service as it is already taken.");
		return FALSE;
	}

	if (!dbus_g_proxy_call (priv->proxy, "RequestName", &err,
							G_TYPE_STRING, NM_DBUS_SERVICE_SYSTEM_SETTINGS,
							G_TYPE_UINT, DBUS_NAME_FLAG_DO_NOT_QUEUE,
							G_TYPE_INVALID,
							G_TYPE_UINT, &result,
							G_TYPE_INVALID)) {
		nm_log_warn (LOGD_CORE, "Could not acquire the NetworkManagerSystemSettings service.\n"
		             "  Message: '%s'", err->message);
		g_error_free (err);
		return FALSE;
	}

	if (result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		nm_log_warn (LOGD_CORE, "Could not acquire the NetworkManagerSystemSettings service "
		             "as it is already taken.");
		return FALSE;
	}

	priv->started = TRUE;
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
