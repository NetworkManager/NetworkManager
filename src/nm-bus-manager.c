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
 * Copyright (C) 2006 - 2013 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>

#include "nm-dbus-interface.h"
#include "nm-bus-manager.h"
#include "nm-core-internal.h"
#include "nm-dbus-compat.h"
#include "nm-exported-object.h"
#include "NetworkManagerUtils.h"

#define _NMLOG_DOMAIN       LOGD_CORE
#define _NMLOG_PREFIX_NAME  "bus-manager"
#define _NMLOG(level, ...) \
    G_STMT_START { \
        nm_log ((level), _NMLOG_DOMAIN, \
                "%s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                _NMLOG_PREFIX_NAME": " \
                _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    } G_STMT_END

enum {
	DBUS_CONNECTION_CHANGED = 0,
	PRIVATE_CONNECTION_NEW,
	PRIVATE_CONNECTION_DISCONNECTED,
	NUMBER_OF_SIGNALS
};

static guint signals[NUMBER_OF_SIGNALS];

G_DEFINE_TYPE(NMBusManager, nm_bus_manager, G_TYPE_OBJECT)

#define NM_BUS_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                        NM_TYPE_BUS_MANAGER, \
                                        NMBusManagerPrivate))

typedef struct _PrivateServer PrivateServer;

typedef struct {
	GDBusConnection *connection;
	GDBusObjectManagerServer *obj_manager;
	gboolean started;

	GSList *private_servers;

	GDBusProxy *proxy;

	gulong bus_closed_id;
	guint reconnect_id;
} NMBusManagerPrivate;

static gboolean nm_bus_manager_init_bus (NMBusManager *self);
static void nm_bus_manager_cleanup (NMBusManager *self);
static void start_reconnection_timeout (NMBusManager *self);

/* The base path for our GDBusObjectManagerServers.  They do not contain
 * "NetworkManager" because GDBusObjectManagerServer requires that all
 * exported objects be *below* the base path, and eg the Manager object
 * is the base path already.
 */
#define OBJECT_MANAGER_SERVER_BASE_PATH "/org/freedesktop"

NM_DEFINE_SINGLETON_REGISTER (NMBusManager);

NMBusManager *
nm_bus_manager_get (void)
{
	if (G_UNLIKELY (!singleton_instance)) {
		nm_bus_manager_setup (g_object_new (NM_TYPE_BUS_MANAGER, NULL));
		if (!nm_bus_manager_init_bus (singleton_instance))
			start_reconnection_timeout (singleton_instance);
	}
	return singleton_instance;
}

void
nm_bus_manager_setup (NMBusManager *instance)
{
	static char already_setup = FALSE;

	g_assert (NM_IS_BUS_MANAGER (instance));
	g_assert (!already_setup);
	g_assert (!singleton_instance);

	already_setup = TRUE;
	singleton_instance = instance;
	nm_singleton_instance_register ();
	_LOGD ("setup %s singleton (%p)", "NMBusManager", singleton_instance);
}

/**************************************************************/

struct _PrivateServer {
	const char *tag;
	GQuark detail;
	char *address;
	GDBusServer *server;

	/* With peer bus connections, we'll get a new connection for each
	 * client.  For each connection we create an ObjectManager for
	 * that connection to handle exporting our objects.  This table
	 * maps GDBusObjectManager :: 'fake sender'.
	 *
	 * Note that even for connections that don't export any objects
	 * we'll still create GDBusObjectManager since that's where we store
	 * the pointer to the GDBusConnection.
	 */
	GHashTable *obj_managers;

	NMBusManager *manager;
};

typedef struct {
	GDBusConnection *connection;
	PrivateServer *server;
	gboolean remote_peer_vanished;
} CloseConnectionInfo;

static gboolean
close_connection_in_idle (gpointer user_data)
{
	CloseConnectionInfo *info = user_data;
	PrivateServer *server = info->server;
	GHashTableIter iter;
	GDBusObjectManagerServer *manager;

	/* Emit this for the manager */
	g_signal_emit (server->manager,
	               signals[PRIVATE_CONNECTION_DISCONNECTED],
	               server->detail,
	               info->connection);

	/* FIXME: there's a bug (754730) in GLib for which the connection
	 * is marked as closed when the remote peer vanishes but its
	 * resources are not cleaned up.  Work around it by explicitly
	 * closing the connection in that case. */
	if (info->remote_peer_vanished)
		g_dbus_connection_close (info->connection, NULL, NULL, NULL);

	g_hash_table_iter_init (&iter, server->obj_managers);
	while (g_hash_table_iter_next (&iter, (gpointer) &manager, NULL)) {
		if (g_dbus_object_manager_server_get_connection (manager) == info->connection) {
			g_hash_table_iter_remove (&iter);
			break;
		}
	}

	g_object_unref (server->manager);
	g_slice_free (CloseConnectionInfo, info);

	return G_SOURCE_REMOVE;
}

static void
private_server_closed_connection (GDBusConnection *conn,
                                  gboolean remote_peer_vanished,
                                  GError *error,
                                  gpointer user_data)
{
	PrivateServer *s = user_data;
	CloseConnectionInfo *info;

	/* Clean up after the connection */
	_LOGD ("(%s) closed connection %p on private socket", s->tag, conn);

	info = g_slice_new0 (CloseConnectionInfo);
	info->connection = conn;
	info->server = s;
	info->remote_peer_vanished = remote_peer_vanished;

	g_object_ref (s->manager);

	/* Delay the close of connection to ensure that D-Bus signals
	 * are handled */
	g_idle_add (close_connection_in_idle, info);
}

static gboolean
private_server_new_connection (GDBusServer *server,
                               GDBusConnection *conn,
                               gpointer user_data)
{
	PrivateServer *s = user_data;
	static guint32 counter = 0;
	GDBusObjectManagerServer *manager;
	char *sender;

	g_signal_connect (conn, "closed", G_CALLBACK (private_server_closed_connection), s);

	/* Fake a sender since private connections don't have one */
	sender = g_strdup_printf ("x:y:%d", counter++);

	manager = g_dbus_object_manager_server_new (OBJECT_MANAGER_SERVER_BASE_PATH);
	g_dbus_object_manager_server_set_connection (manager, conn);
	g_hash_table_insert (s->obj_managers, manager, sender);

	_LOGD ("(%s) accepted connection %p on private socket", s->tag, conn);

	/* Emit this for the manager */
	g_signal_emit (s->manager,
	               signals[PRIVATE_CONNECTION_NEW],
	               s->detail,
	               conn,
	               manager);
	return TRUE;
}

static void
private_server_manager_destroy (GDBusObjectManagerServer *manager)
{
	GDBusConnection *connection = g_dbus_object_manager_server_get_connection (manager);

	if (!g_dbus_connection_is_closed (connection))
		g_dbus_connection_close (connection, NULL, NULL, NULL);
	g_dbus_object_manager_server_set_connection (manager, NULL);
	g_object_unref (manager);
}

static gboolean
private_server_authorize (GDBusAuthObserver *observer,
                          GIOStream         *stream,
                          GCredentials      *credentials,
                          gpointer           user_data)
{
	return g_credentials_get_unix_user (credentials, NULL) == 0;
}

static PrivateServer *
private_server_new (const char *path,
                    const char *tag,
                    NMBusManager *manager)
{
	PrivateServer *s;
	GDBusAuthObserver *auth_observer;
	GDBusServer *server;
	GError *error = NULL;
	char *address, *guid;

	unlink (path);
	address = g_strdup_printf ("unix:path=%s", path);

	_LOGD ("(%s) creating private socket %s", tag, address);

	guid = g_dbus_generate_guid ();
	auth_observer = g_dbus_auth_observer_new ();
	g_signal_connect (auth_observer, "authorize-authenticated-peer",
	                  G_CALLBACK (private_server_authorize), NULL);
	server = g_dbus_server_new_sync (address,
	                                 G_DBUS_SERVER_FLAGS_NONE,
	                                 guid,
	                                 auth_observer,
	                                 NULL, &error);
	g_free (guid);
	g_object_unref (auth_observer);

	if (!server) {
		_LOGW ("(%s) failed to set up private socket %s: %s",
		       tag, address, error->message);
		g_error_free (error);
		g_free (address);
		return NULL;
	}

	s = g_malloc0 (sizeof (*s));
	s->address = address;
	s->server = server;
	g_signal_connect (server, "new-connection",
	                  G_CALLBACK (private_server_new_connection), s);

	s->obj_managers = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                         (GDestroyNotify) private_server_manager_destroy,
	                                         g_free);
	s->manager = manager;
	s->detail = g_quark_from_string (tag);
	s->tag = g_quark_to_string (s->detail);

	g_dbus_server_start (server);

	return s;
}

static void
private_server_free (gpointer ptr)
{
	PrivateServer *s = ptr;

	unlink (s->address);
	g_free (s->address);
	g_hash_table_destroy (s->obj_managers);

	g_dbus_server_stop (s->server);
	g_object_unref (s->server);

	memset (s, 0, sizeof (*s));
	g_free (s);
}

void
nm_bus_manager_private_server_register (NMBusManager *self,
                                        const char *path,
                                        const char *tag)
{
	NMBusManagerPrivate *priv = NM_BUS_MANAGER_GET_PRIVATE (self);
	PrivateServer *s;
	GSList *iter;

	g_return_if_fail (self != NULL);
	g_return_if_fail (path != NULL);
	g_return_if_fail (tag != NULL);

	/* Only one instance per tag; but don't warn */
	for (iter = priv->private_servers; iter; iter = g_slist_next (iter)) {
		s = iter->data;
		if (g_strcmp0 (tag, s->tag) == 0)
			return;
	}

	s = private_server_new (path, tag, self);
	if (s)
		priv->private_servers = g_slist_append (priv->private_servers, s);
}

static const char *
private_server_get_connection_owner (PrivateServer *s, GDBusConnection *connection)
{
	GHashTableIter iter;
	GDBusObjectManagerServer *manager;
	const char *owner;

	g_return_val_if_fail (s != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);

	g_hash_table_iter_init (&iter, s->obj_managers);
	while (g_hash_table_iter_next (&iter, (gpointer) &manager, (gpointer) &owner)) {
		if (g_dbus_object_manager_server_get_connection (manager) == connection)
			return owner;
	}
	return NULL;
}

static GDBusConnection *
private_server_get_connection_by_owner (PrivateServer *s, const char *owner)
{
	GHashTableIter iter;
	GDBusObjectManagerServer *manager;
	const char *priv_sender;

	g_hash_table_iter_init (&iter, s->obj_managers);
	while (g_hash_table_iter_next (&iter, (gpointer) &manager, (gpointer) &priv_sender)) {
		if (g_strcmp0 (owner, priv_sender) == 0)
			return g_dbus_object_manager_server_get_connection (manager);
	}
	return NULL;
}

/**************************************************************/

static gboolean
_bus_get_unix_pid (NMBusManager *self,
                   const char *sender,
                   gulong *out_pid,
                   GError **error)
{
	guint32 unix_pid = G_MAXUINT32;
	gs_unref_variant GVariant *ret = NULL;

	ret = _nm_dbus_proxy_call_sync (NM_BUS_MANAGER_GET_PRIVATE (self)->proxy,
	                                "GetConnectionUnixProcessID",
	                                g_variant_new ("(s)", sender),
	                                G_VARIANT_TYPE ("(u)"),
	                                G_DBUS_CALL_FLAGS_NONE, 2000,
	                                NULL, error);
	if (!ret)
		return FALSE;

	g_variant_get (ret, "(u)", &unix_pid);

	*out_pid = (gulong) unix_pid;
	return TRUE;
}

static gboolean
_bus_get_unix_user (NMBusManager *self,
                    const char *sender,
                    gulong *out_user,
                    GError **error)
{
	guint32 unix_uid = G_MAXUINT32;
	gs_unref_variant GVariant *ret = NULL;

	ret = _nm_dbus_proxy_call_sync (NM_BUS_MANAGER_GET_PRIVATE (self)->proxy,
	                                "GetConnectionUnixUser",
	                                g_variant_new ("(s)", sender),
	                                G_VARIANT_TYPE ("(u)"),
	                                G_DBUS_CALL_FLAGS_NONE, 2000,
	                                NULL, error);
	if (!ret)
		return FALSE;

	g_variant_get (ret, "(u)", &unix_uid);

	*out_user = (gulong) unix_uid;
	return TRUE;
}

/**
 * _get_caller_info():
 *
 * Given a GDBus method invocation, or a GDBusConnection + GDBusMessage,
 * return the sender and the UID of the sender.
 */
static gboolean
_get_caller_info (NMBusManager *self,
                  GDBusMethodInvocation *context,
                  GDBusConnection *connection,
                  GDBusMessage *message,
                  char **out_sender,
                  gulong *out_uid,
                  gulong *out_pid)
{
	NMBusManagerPrivate *priv = NM_BUS_MANAGER_GET_PRIVATE (self);
	const char *sender;
	GSList *iter;

	if (context) {
		connection = g_dbus_method_invocation_get_connection (context);

		/* only bus connections will have a sender */
		sender = g_dbus_method_invocation_get_sender (context);
	} else {
		g_assert (message);
		sender = g_dbus_message_get_sender (message);
	}
	g_assert (connection);

	if (!sender) {
		/* Might be a private connection, for which we fake a sender */
		for (iter = priv->private_servers; iter; iter = g_slist_next (iter)) {
			PrivateServer *s = iter->data;

			sender = private_server_get_connection_owner (s, connection);
			if (sender) {
				if (out_uid)
					*out_uid = 0;
				if (out_sender)
					*out_sender = g_strdup (sender);
				if (out_pid) {
					GCredentials *creds;

					creds = g_dbus_connection_get_peer_credentials (connection);
					if (creds) {
						pid_t pid;

						pid = g_credentials_get_unix_pid (creds, NULL);
						if (pid == -1)
							*out_pid = G_MAXULONG;
						else
							*out_pid = pid;
					} else
						*out_pid = G_MAXULONG;
				}
				return TRUE;
			}
		}
		return FALSE;
	}

	/* Bus connections always have a sender */
	g_assert (sender);
	if (out_uid) {
		if (!_bus_get_unix_user (self, sender, out_uid, NULL)) {
			*out_uid = G_MAXULONG;
			return FALSE;
		}
	}

	if (out_pid) {
		if (!_bus_get_unix_pid (self, sender, out_pid, NULL)) {
			*out_pid = G_MAXULONG;
			return FALSE;
		}
	}

	if (out_sender)
		*out_sender = g_strdup (sender);

	return TRUE;
}

gboolean
nm_bus_manager_get_caller_info (NMBusManager *self,
                                GDBusMethodInvocation *context,
                                char **out_sender,
                                gulong *out_uid,
                                gulong *out_pid)
{
	return _get_caller_info (self, context, NULL, NULL, out_sender, out_uid, out_pid);
}

gboolean
nm_bus_manager_get_caller_info_from_message (NMBusManager *self,
                                             GDBusConnection *connection,
                                             GDBusMessage *message,
                                             char **out_sender,
                                             gulong *out_uid,
                                             gulong *out_pid)
{
	return _get_caller_info (self, NULL, connection, message, out_sender, out_uid, out_pid);
}

gboolean
nm_bus_manager_get_unix_user (NMBusManager *self,
                              const char *sender,
                              gulong *out_uid)
{
	NMBusManagerPrivate *priv = NM_BUS_MANAGER_GET_PRIVATE (self);
	GSList *iter;
	GError *error = NULL;

	g_return_val_if_fail (sender != NULL, FALSE);
	g_return_val_if_fail (out_uid != NULL, FALSE);

	/* Check if it's a private connection sender, which we fake */
	for (iter = priv->private_servers; iter; iter = iter->next) {
		if (private_server_get_connection_by_owner (iter->data, sender)) {
			*out_uid = 0;
			return TRUE;
		}
	}

	/* Otherwise, a bus connection */
	if (!_bus_get_unix_user (self, sender, out_uid, &error)) {
		_LOGW ("failed to get unix user for dbus sender '%s': %s",
		       sender, error->message);
		g_error_free (error);
		return FALSE;
	}

	return TRUE;
}

/**************************************************************/

static void
nm_bus_manager_init (NMBusManager *self)
{
	NMBusManagerPrivate *priv = NM_BUS_MANAGER_GET_PRIVATE (self);

	priv->obj_manager = g_dbus_object_manager_server_new (OBJECT_MANAGER_SERVER_BASE_PATH);
}

static void
nm_bus_manager_dispose (GObject *object)
{
	NMBusManager *self = NM_BUS_MANAGER (object);
	NMBusManagerPrivate *priv = NM_BUS_MANAGER_GET_PRIVATE (self);
	GList *exported, *iter;

	g_slist_free_full (priv->private_servers, private_server_free);
	priv->private_servers = NULL;

	nm_bus_manager_cleanup (self);

	if (priv->obj_manager) {
		/* The ObjectManager owns the last reference to many exported
		 * objects, and when that reference is dropped the objects unregister
		 * themselves via nm_bus_manager_unregister_object().  By that time
		 * priv->obj_manager is already NULL and that prints warnings.  Unregister
		 * them before clearing the ObjectManager instead.
		 */
		exported = g_dbus_object_manager_get_objects ((GDBusObjectManager *) priv->obj_manager);
		for (iter = exported; iter; iter = iter->next) {
			nm_bus_manager_unregister_object (self, iter->data);
			g_object_unref (iter->data);
		}
		g_list_free (exported);
		g_clear_object (&priv->obj_manager);
	}

	nm_clear_g_source (&priv->reconnect_id);

	G_OBJECT_CLASS (nm_bus_manager_parent_class)->dispose (object);
}

static void
nm_bus_manager_class_init (NMBusManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMBusManagerPrivate));

	object_class->dispose = nm_bus_manager_dispose;

	signals[DBUS_CONNECTION_CHANGED] =
		g_signal_new (NM_BUS_MANAGER_DBUS_CONNECTION_CHANGED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMBusManagerClass, dbus_connection_changed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);

	signals[PRIVATE_CONNECTION_NEW] =
		g_signal_new (NM_BUS_MANAGER_PRIVATE_CONNECTION_NEW,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_DBUS_CONNECTION, G_TYPE_DBUS_OBJECT_MANAGER_SERVER);

	signals[PRIVATE_CONNECTION_DISCONNECTED] =
		g_signal_new (NM_BUS_MANAGER_PRIVATE_CONNECTION_DISCONNECTED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
		              G_STRUCT_OFFSET (NMBusManagerClass, private_connection_disconnected),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);
}


/* Only cleanup a specific dbus connection, not all our private data */
static void
nm_bus_manager_cleanup (NMBusManager *self)
{
	NMBusManagerPrivate *priv = NM_BUS_MANAGER_GET_PRIVATE (self);

	g_clear_object (&priv->proxy);

	if (priv->connection) {
		g_signal_handler_disconnect (priv->connection, priv->bus_closed_id);
		priv->bus_closed_id = 0;
		g_clear_object (&priv->connection);
	}

	g_dbus_object_manager_server_set_connection (priv->obj_manager, NULL);
	priv->started = FALSE;
}

static gboolean
nm_bus_manager_reconnect (gpointer user_data)
{
	NMBusManager *self = NM_BUS_MANAGER (user_data);
	NMBusManagerPrivate *priv = NM_BUS_MANAGER_GET_PRIVATE (self);

	g_assert (self != NULL);

	if (nm_bus_manager_init_bus (self)) {
		if (nm_bus_manager_start_service (self)) {
			_LOGI ("reconnected to the system bus");
			g_signal_emit (self, signals[DBUS_CONNECTION_CHANGED],
			               0, priv->connection);
			priv->reconnect_id = 0;
			return FALSE;
		}
	}

	/* Try again */
	nm_bus_manager_cleanup (self);
	return TRUE;
}

static void
start_reconnection_timeout (NMBusManager *self)
{
	NMBusManagerPrivate *priv = NM_BUS_MANAGER_GET_PRIVATE (self);

	if (priv->reconnect_id)
		g_source_remove (priv->reconnect_id);

	/* Schedule timeout for reconnection attempts */
	priv->reconnect_id = g_timeout_add_seconds (3, nm_bus_manager_reconnect, self);
}

static void
closed_cb (GDBusConnection *connection,
           gboolean remote_peer_vanished,
           GError *error,
           gpointer user_data)
{
	NMBusManager *self = NM_BUS_MANAGER (user_data);

	/* Clean up existing connection */
	_LOGW ("disconnected by the system bus");

	nm_bus_manager_cleanup (self);

	g_signal_emit (G_OBJECT (self), signals[DBUS_CONNECTION_CHANGED], 0, NULL);

	start_reconnection_timeout (self);
}

static gboolean
nm_bus_manager_init_bus (NMBusManager *self)
{
	NMBusManagerPrivate *priv = NM_BUS_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;

	if (priv->connection) {
		_LOGW ("DBus Manager already has a valid connection");
		return FALSE;
	}

	priv->connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
	if (!priv->connection) {
		/* Log with 'info' severity; there won't be a bus daemon in minimal
		 * environments (eg, initrd) where we only want to use the private
		 * socket.
		 */
		_LOGI ("could not connect to the system bus (%s); only the "
		       "private D-Bus socket will be available",
		       error->message);
		g_error_free (error);
		return FALSE;
	}

	g_dbus_connection_set_exit_on_close (priv->connection, FALSE);
	priv->bus_closed_id = g_signal_connect (priv->connection, "closed",
	                                        G_CALLBACK (closed_cb), self);

	priv->proxy = g_dbus_proxy_new_sync (priv->connection,
	                                     G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                                         G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
	                                     NULL,
	                                     DBUS_SERVICE_DBUS,
	                                     DBUS_PATH_DBUS,
	                                     DBUS_INTERFACE_DBUS,
	                                     NULL, &error);
	if (!priv->proxy) {
		g_clear_object (&priv->connection);
		_LOGW ("could not create org.freedesktop.DBus proxy (%s); only the "
		       "private D-Bus socket will be available",
		       error->message);
		g_error_free (error);
		return FALSE;
	}

	g_dbus_object_manager_server_set_connection (priv->obj_manager, priv->connection);
	return TRUE;
}

/* Register our service on the bus; shouldn't be called until
 * all necessary message handlers have been registered, because
 * when we register on the bus, clients may start to call.
 */
gboolean
nm_bus_manager_start_service (NMBusManager *self)
{
	NMBusManagerPrivate *priv;
	gs_unref_variant GVariant *ret = NULL;
	int result;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_BUS_MANAGER (self), FALSE);

	priv = NM_BUS_MANAGER_GET_PRIVATE (self);

	if (priv->started) {
		_LOGE ("service has already started");
		return FALSE;
	}

	/* Pointless to request a name when we aren't connected to the bus */
	if (!priv->proxy)
		return FALSE;

	ret = _nm_dbus_proxy_call_sync (priv->proxy,
	                                "RequestName",
	                                g_variant_new ("(su)",
	                                               NM_DBUS_SERVICE,
	                                               DBUS_NAME_FLAG_DO_NOT_QUEUE),
	                                G_VARIANT_TYPE ("(u)"),
	                                G_DBUS_CALL_FLAGS_NONE, -1,
	                                NULL, &err);
	if (!ret) {
		_LOGE ("could not acquire the NetworkManager service: '%s'", err->message);
		g_error_free (err);
		return FALSE;
	}

	g_variant_get (ret, "(u)", &result);

	if (result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		_LOGE ("could not acquire the NetworkManager service as it is already taken");
		return FALSE;
	}

	priv->started = TRUE;
	return priv->started;
}

GDBusConnection *
nm_bus_manager_get_connection (NMBusManager *self)
{
	g_return_val_if_fail (NM_IS_BUS_MANAGER (self), NULL);

	return NM_BUS_MANAGER_GET_PRIVATE (self)->connection;
}

void
nm_bus_manager_register_object (NMBusManager *self,
                                GDBusObjectSkeleton *object)
{
	NMBusManagerPrivate *priv;

	g_return_if_fail (NM_IS_BUS_MANAGER (self));
	g_return_if_fail (NM_IS_EXPORTED_OBJECT (object));

	priv = NM_BUS_MANAGER_GET_PRIVATE (self);

#if NM_MORE_ASSERTS >= 1
#if GLIB_CHECK_VERSION(2,34,0)
	if (g_dbus_object_manager_server_is_exported (priv->obj_manager, object))
		g_return_if_reached ();
#endif
#endif

	g_dbus_object_manager_server_export (priv->obj_manager, object);
}

GDBusObjectSkeleton *
nm_bus_manager_get_registered_object (NMBusManager *self,
                                      const char *path)
{
	NMBusManagerPrivate *priv = NM_BUS_MANAGER_GET_PRIVATE (self);

	return G_DBUS_OBJECT_SKELETON (g_dbus_object_manager_get_object ((GDBusObjectManager *) priv->obj_manager, path));
}

void
nm_bus_manager_unregister_object (NMBusManager *self,
                                  GDBusObjectSkeleton *object)
{
	NMBusManagerPrivate *priv;
	gs_free char *path = NULL;

	g_return_if_fail (NM_IS_BUS_MANAGER (self));
	g_return_if_fail (NM_IS_EXPORTED_OBJECT (object));

	priv = NM_BUS_MANAGER_GET_PRIVATE (self);

#if NM_MORE_ASSERTS >= 1
#if GLIB_CHECK_VERSION(2,34,0)
	if (!g_dbus_object_manager_server_is_exported (priv->obj_manager, object))
		g_return_if_reached ();
#endif
#endif

	g_object_get (G_OBJECT (object), "g-object-path", &path, NULL);
	g_return_if_fail (path != NULL);

	g_dbus_object_manager_server_unexport (priv->obj_manager, path);
}

const char *
nm_bus_manager_connection_get_private_name (NMBusManager *self,
                                            GDBusConnection *connection)
{
	NMBusManagerPrivate *priv;
	GSList *iter;
	const char *owner;

	g_return_val_if_fail (NM_IS_BUS_MANAGER (self), FALSE);
	g_return_val_if_fail (G_IS_DBUS_CONNECTION (connection), FALSE);

	if (g_dbus_connection_get_unique_name (connection)) {
		/* Shortcut. The connection is not a private connection. */
		return NULL;
	}

	priv = NM_BUS_MANAGER_GET_PRIVATE (self);
	for (iter = priv->private_servers; iter; iter = g_slist_next (iter)) {
		PrivateServer *s = iter->data;

		if ((owner = private_server_get_connection_owner (s, connection)))
			return owner;
	}
	g_return_val_if_reached (NULL);
}

/**
 * nm_bus_manager_new_proxy:
 * @self: the #NMBusManager
 * @connection: the GDBusConnection for which this connection should be created
 * @proxy_type: the type of #GDBusProxy to create
 * @name: any name on the message bus
 * @path: name of the object instance to call methods on
 * @iface: name of the interface to call methods on
 *
 * Creates a new proxy (of type @proxy_type) for a name on a given bus.  Since
 * the process which called the D-Bus method could be coming from a private
 * connection or the system bus connection, different proxies must be created
 * for each case.  This function abstracts that.
 *
 * Returns: a #GDBusProxy capable of calling D-Bus methods of the calling process
 */
GDBusProxy *
nm_bus_manager_new_proxy (NMBusManager *self,
                          GDBusConnection *connection,
                          GType proxy_type,
                          const char *name,
                          const char *path,
                          const char *iface)
{
	const char *owner;
	GDBusProxy *proxy;
	GError *error = NULL;

	g_return_val_if_fail (g_type_is_a (proxy_type, G_TYPE_DBUS_PROXY), NULL);
	g_return_val_if_fail (G_IS_DBUS_CONNECTION (connection), NULL);

	/* Might be a private connection, for which @name is fake */
	owner = nm_bus_manager_connection_get_private_name (self, connection);
	if (owner) {
		g_return_val_if_fail (!g_strcmp0 (owner, name), NULL);
		name = NULL;
	}

	proxy = g_initable_new (proxy_type, NULL, &error,
	                        "g-connection", connection,
	                        "g-flags", (G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                                    G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS),
	                        "g-name", name,
	                        "g-object-path", path,
	                        "g-interface-name", iface,
	                        NULL);
	if (!proxy) {
		_LOGW ("could not create proxy for %s on connection %s: %s",
		       iface, name, error->message);
		g_error_free (error);
	}
	return proxy;
}
