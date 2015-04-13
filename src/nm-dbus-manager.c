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

#include "config.h"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#include "nm-dbus-interface.h"
#include "nm-dbus-manager.h"
#include "nm-glib-compat.h"
#include "nm-properties-changed-signal.h"

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <string.h>
#include "nm-logging.h"
#include "NetworkManagerUtils.h"

#define PRIV_SOCK_PATH NMRUNDIR "/private"
#define PRIV_SOCK_TAG  "private"

enum {
	DBUS_CONNECTION_CHANGED = 0,
	NAME_OWNER_CHANGED,
	PRIVATE_CONNECTION_NEW,
	PRIVATE_CONNECTION_DISCONNECTED,
	NUMBER_OF_SIGNALS
};

static guint signals[NUMBER_OF_SIGNALS];

G_DEFINE_TYPE(NMDBusManager, nm_dbus_manager, G_TYPE_OBJECT)

#define NM_DBUS_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                        NM_TYPE_DBUS_MANAGER, \
                                        NMDBusManagerPrivate))

typedef struct _PrivateServer PrivateServer;

typedef struct {
	DBusConnection *connection;
	DBusGConnection *g_connection;
	GHashTable *exported;
	gboolean started;

	GSList *private_servers;
	PrivateServer *priv_server;

	DBusGProxy *proxy;
	guint proxy_destroy_id;

	guint reconnect_id;
} NMDBusManagerPrivate;

static gboolean nm_dbus_manager_init_bus (NMDBusManager *self);
static void nm_dbus_manager_cleanup (NMDBusManager *self, gboolean dispose);
static void start_reconnection_timeout (NMDBusManager *self);
static void object_destroyed (NMDBusManager *self, gpointer object);

NM_DEFINE_SINGLETON_DESTRUCTOR (NMDBusManager);
NM_DEFINE_SINGLETON_WEAK_REF (NMDBusManager);

NMDBusManager *
nm_dbus_manager_get (void)
{
	if (G_UNLIKELY (!singleton_instance)) {
		nm_dbus_manager_setup (g_object_new (NM_TYPE_DBUS_MANAGER, NULL));
		if (!nm_dbus_manager_init_bus (singleton_instance))
			start_reconnection_timeout (singleton_instance);
	}
	return singleton_instance;
}

void
nm_dbus_manager_setup (NMDBusManager *instance)
{
	static char already_setup = FALSE;

	g_assert (NM_IS_DBUS_MANAGER (instance));
	g_assert (!already_setup);
	g_assert (!singleton_instance);

	already_setup = TRUE;
	singleton_instance = instance;
	nm_singleton_instance_weak_ref_register ();
	nm_log_dbg (LOGD_CORE, "create %s singleton (%p)", "NMDBusManager", singleton_instance);
}

/**************************************************************/

struct _PrivateServer {
	const char *tag;
	GQuark detail;
	char *address;
	DBusServer *server;
	GHashTable *connections;
	NMDBusManager *manager;
};

static DBusHandlerResult
private_server_message_filter (DBusConnection *conn,
                               DBusMessage *message,
                               void *data)
{
	PrivateServer *s = data;
	int fd;

	/* Clean up after the connection */
	if (dbus_message_is_signal (message, DBUS_INTERFACE_LOCAL, "Disconnected")) {
		nm_log_dbg (LOGD_CORE, "(%s) closed connection %p on private socket (fd %d).",
		            s->tag, conn, dbus_connection_get_unix_fd (conn, &fd) ? fd : -1);

		/* Emit this for the manager */
		g_signal_emit (s->manager,
		               signals[PRIVATE_CONNECTION_DISCONNECTED],
		               s->detail,
		               dbus_connection_get_g_connection (conn));

		g_hash_table_remove (s->connections, conn);

		/* Let dbus-glib process the message too */
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static dbus_bool_t
allow_only_root (DBusConnection *connection, unsigned long uid, void *data)
{
	return uid == 0;
}

static void
private_server_new_connection (DBusServer *server,
                               DBusConnection *conn,
                               gpointer user_data)
{
	PrivateServer *s = user_data;
	static guint32 counter = 0;
	char *sender;
	int fd;

	if (!dbus_connection_add_filter (conn, private_server_message_filter, s, NULL)) {
		dbus_connection_close (conn);
		return;
	}
	dbus_connection_set_unix_user_function (conn, allow_only_root, NULL, NULL);
	dbus_connection_setup_with_g_main (conn, NULL);

	/* Fake a sender since private connections don't have one */
	sender = g_strdup_printf ("x:y:%d", counter++);
	g_hash_table_insert (s->connections, dbus_connection_ref (conn), sender);

	nm_log_dbg (LOGD_CORE, "(%s) accepted connection %p on private socket (fd %d).",
	            s->tag, conn, dbus_connection_get_unix_fd (conn, &fd) ? fd : -1);

	/* Emit this for the manager */
	g_signal_emit (s->manager,
	               signals[PRIVATE_CONNECTION_NEW],
	               s->detail,
	               dbus_connection_get_g_connection (conn));
}

static void
private_server_dbus_connection_destroy (DBusConnection *conn)
{
	if (dbus_connection_get_is_connected (conn))
		dbus_connection_close (conn);
	dbus_connection_unref (conn);
}

static PrivateServer *
private_server_new (const char *path,
                    const char *tag,
                    NMDBusManager *manager)
{
	PrivateServer *s;
	DBusServer *server;
	DBusError error;
	char *address;

	unlink (path);
	address = g_strdup_printf ("unix:path=%s", path);

	nm_log_dbg (LOGD_CORE, "(%s) creating private socket %s.", tag, address);

	dbus_error_init (&error);
	server = dbus_server_listen (address, &error);
	if (!server) {
		nm_log_warn (LOGD_CORE, "(%s) failed to set up private socket %s: %s",
		             tag, address, error.message);
		dbus_error_free (&error);
		g_free (address);
		return NULL;
	}

	s = g_malloc0 (sizeof (*s));
	s->address = address;
	s->server = server;
	dbus_server_setup_with_g_main (s->server, NULL);
	dbus_server_set_new_connection_function (s->server, private_server_new_connection, s, NULL);

	s->connections = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                        (GDestroyNotify) private_server_dbus_connection_destroy,
	                                        g_free);
	s->manager = manager;
	s->detail = g_quark_from_string (tag);
	s->tag = g_quark_to_string (s->detail);

	return s;
}

static void
private_server_free (gpointer ptr)
{
	PrivateServer *s = ptr;

	unlink (s->address);
	g_free (s->address);
	g_hash_table_destroy (s->connections);
	dbus_server_disconnect (s->server);
	dbus_server_unref (s->server);
	memset (s, 0, sizeof (*s));
	g_free (s);
}

void
nm_dbus_manager_private_server_register (NMDBusManager *self,
                                         const char *path,
                                         const char *tag)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	PrivateServer *s;
	GSList *iter;

#if !HAVE_DBUS_GLIB_100
	g_assert_not_reached ();
#endif

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
private_server_get_connection_owner (PrivateServer *s, DBusGConnection *connection)
{
	g_return_val_if_fail (s != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);

	return g_hash_table_lookup (s->connections, dbus_g_connection_get_connection (connection));
}

/**************************************************************/

static gboolean
_bus_get_unix_pid (NMDBusManager *self,
                   const char *sender,
                   gulong *out_pid,
                   GError **error)
{
	guint32 unix_pid = G_MAXUINT32;

	if (!dbus_g_proxy_call_with_timeout (NM_DBUS_MANAGER_GET_PRIVATE (self)->proxy,
	                                     "GetConnectionUnixProcessID", 2000, error,
	                                     G_TYPE_STRING, sender,
	                                     G_TYPE_INVALID,
	                                     G_TYPE_UINT, &unix_pid,
	                                     G_TYPE_INVALID)) {
		return FALSE;
	}

	*out_pid = (gulong) unix_pid;
	return TRUE;
}

/**
 * _get_caller_info_from_context():
 *
 * Given a dbus-glib method invocation, or a DBusConnection + DBusMessage,
 * return the sender and the UID of the sender.
 */
static gboolean
_get_caller_info (NMDBusManager *self,
                  DBusGMethodInvocation *context,
                  DBusConnection *connection,
                  DBusMessage *message,
                  char **out_sender,
                  gulong *out_uid,
                  gulong *out_pid)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	DBusGConnection *gconn;
	char *sender;
	const char *priv_sender;
	DBusError error;
	GSList *iter;

	if (context) {
		gconn = dbus_g_method_invocation_get_g_connection (context);
		g_assert (gconn);
		connection = dbus_g_connection_get_connection (gconn);

		/* only bus connections will have a sender */
		sender = dbus_g_method_get_sender (context);
	} else {
		g_assert (message);
		sender = g_strdup (dbus_message_get_sender (message));
	}
	g_assert (connection);

	if (!sender) {
		/* Might be a private connection, for which we fake a sender */
		for (iter = priv->private_servers; iter; iter = g_slist_next (iter)) {
			PrivateServer *s = iter->data;

			priv_sender = g_hash_table_lookup (s->connections, connection);
			if (priv_sender) {
				if (out_uid)
					*out_uid = 0;
				if (out_sender)
					*out_sender = g_strdup (priv_sender);
				if (out_pid) {
					if (!dbus_connection_get_unix_process_id (connection, out_pid))
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
		dbus_error_init (&error);
		*out_uid = dbus_bus_get_unix_user (connection, sender, &error);
		if (dbus_error_is_set (&error)) {
			dbus_error_free (&error);
			*out_uid = G_MAXULONG;
			g_free (sender);
			return FALSE;
		}
	}

	if (out_pid) {
		if (!_bus_get_unix_pid (self, sender, out_pid, NULL)) {
			*out_pid = G_MAXULONG;
			g_free (sender);
			return FALSE;
		}
	}

	if (out_sender)
		*out_sender = g_strdup (sender);

	g_free (sender);
	return TRUE;
}

gboolean
nm_dbus_manager_get_caller_info (NMDBusManager *self,
                                 DBusGMethodInvocation *context,
                                 char **out_sender,
                                 gulong *out_uid,
                                 gulong *out_pid)
{
	return _get_caller_info (self, context, NULL, NULL, out_sender, out_uid, out_pid);
}

gboolean
nm_dbus_manager_get_caller_info_from_message (NMDBusManager *self,
                                              DBusConnection *connection,
                                              DBusMessage *message,
                                              char **out_sender,
                                              gulong *out_uid,
                                              gulong *out_pid)
{
	return _get_caller_info (self, NULL, connection, message, out_sender, out_uid, out_pid);
}

gboolean
nm_dbus_manager_get_unix_user (NMDBusManager *self,
                               const char *sender,
                               gulong *out_uid)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	GSList *iter;
	DBusError error;

	g_return_val_if_fail (sender != NULL, FALSE);
	g_return_val_if_fail (out_uid != NULL, FALSE);

	/* Check if it's a private connection sender, which we fake */
	for (iter = priv->private_servers; iter; iter = g_slist_next (iter)) {
		PrivateServer *s = iter->data;
		GHashTableIter hiter;
		const char *priv_sender;

		g_hash_table_iter_init (&hiter, s->connections);
		while (g_hash_table_iter_next (&hiter, NULL, (gpointer) &priv_sender)) {
			if (g_strcmp0 (sender, priv_sender) == 0) {
				*out_uid = 0;
				return TRUE;
			}
		}
	}

	/* Otherwise, a bus connection */
	dbus_error_init (&error);
	*out_uid = dbus_bus_get_unix_user (priv->connection, sender, &error);
	if (dbus_error_is_set (&error)) {
		nm_log_warn (LOGD_CORE, "Failed to get unix user for dbus sender '%s': %s",
		             sender, error.message);
		return FALSE;
	}

	return TRUE;
}

/**************************************************************/

#if HAVE_DBUS_GLIB_100
static void
private_connection_new (NMDBusManager *self, DBusGConnection *connection)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	GObject *object;
	const char *path;

	/* Register all exported objects on this private connection */
	g_hash_table_iter_init (&iter, priv->exported);
	while (g_hash_table_iter_next (&iter, (gpointer) &object, (gpointer) &path)) {
		dbus_g_connection_register_g_object (connection, path, object);
		nm_log_trace (LOGD_CORE, "(%s) registered %p (%s) at '%s' on private socket.",
		              PRIV_SOCK_TAG, object, G_OBJECT_TYPE_NAME (object), path);
	}
}

static void
private_connection_disconnected (NMDBusManager *self, DBusGConnection *connection)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	const char *owner;

	owner = private_server_get_connection_owner (priv->priv_server, connection);
	g_assert (owner);

	/* Fake a NameOwnerChanged to let listerners know this owner has quit */
	g_signal_emit (G_OBJECT (self), signals[NAME_OWNER_CHANGED],
	               0, owner, owner, NULL);
}

static void
private_server_setup (NMDBusManager *self)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	/* Skip this step if this is just a test program */
	if (nm_utils_get_testing ())
		return;

	/* Set up our main private DBus socket */
	if (mkdir (NMRUNDIR, 0755) == -1) {
		if (errno != EEXIST)
			nm_log_warn (LOGD_CORE, "Error creating directory \"%s\": %d (%s)", NMRUNDIR, errno, g_strerror (errno));
	}
	priv->priv_server = private_server_new (PRIV_SOCK_PATH, PRIV_SOCK_TAG, self);
	if (priv->priv_server) {
		priv->private_servers = g_slist_append (priv->private_servers, priv->priv_server);

		g_signal_connect (self,
		                  NM_DBUS_MANAGER_PRIVATE_CONNECTION_NEW "::" PRIV_SOCK_TAG,
		                  (GCallback) private_connection_new,
		                  NULL);
		g_signal_connect (self,
		                  NM_DBUS_MANAGER_PRIVATE_CONNECTION_DISCONNECTED "::" PRIV_SOCK_TAG,
		                  (GCallback) private_connection_disconnected,
		                  NULL);
	}
}
#endif  /* HAVE_DBUS_GLIB_100 */

static void
nm_dbus_manager_init (NMDBusManager *self)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	priv->exported = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_free);

#if HAVE_DBUS_GLIB_100
	private_server_setup (self);
#endif
}

static void
nm_dbus_manager_dispose (GObject *object)
{
	NMDBusManager *self = NM_DBUS_MANAGER (object);
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	GObject *exported;

	if (priv->exported) {
		g_hash_table_iter_init (&iter, priv->exported);
		while (g_hash_table_iter_next (&iter, (gpointer) &exported, NULL))
			g_object_weak_unref (exported, (GWeakNotify) object_destroyed, self);

		g_hash_table_destroy (priv->exported);
		priv->exported = NULL;
	}

	g_slist_free_full (priv->private_servers, private_server_free);
	priv->private_servers = NULL;
	priv->priv_server = NULL;

	nm_dbus_manager_cleanup (self, TRUE);

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

	g_type_class_add_private (klass, sizeof (NMDBusManagerPrivate));

	object_class->dispose = nm_dbus_manager_dispose;

	signals[DBUS_CONNECTION_CHANGED] =
		g_signal_new (NM_DBUS_MANAGER_DBUS_CONNECTION_CHANGED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMDBusManagerClass, dbus_connection_changed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);

	signals[NAME_OWNER_CHANGED] =
		g_signal_new (NM_DBUS_MANAGER_NAME_OWNER_CHANGED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMDBusManagerClass, name_owner_changed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

	signals[PRIVATE_CONNECTION_NEW] =
		g_signal_new (NM_DBUS_MANAGER_PRIVATE_CONNECTION_NEW,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
		              G_STRUCT_OFFSET (NMDBusManagerClass, private_connection_new),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);

	signals[PRIVATE_CONNECTION_DISCONNECTED] =
		g_signal_new (NM_DBUS_MANAGER_PRIVATE_CONNECTION_DISCONNECTED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
		              G_STRUCT_OFFSET (NMDBusManagerClass, private_connection_disconnected),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);
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

	if (!NM_DBUS_MANAGER_GET_PRIVATE (self)->proxy)
		return NULL;

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

	if (!NM_DBUS_MANAGER_GET_PRIVATE (self)->proxy)
		return FALSE;

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

	if (priv->connection) {
		nm_log_warn (LOGD_CORE, "DBus Manager already has a valid connection.");
		return FALSE;
	}

	dbus_connection_set_change_sigpipe (TRUE);

	priv->g_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, NULL);
	if (!priv->g_connection) {
		/* Log with 'info' severity; there won't be a bus daemon in minimal
		 * environments (eg, initrd) where we only want to use the private
		 * socket.
		 */
		nm_log_info (LOGD_CORE, "Could not connect to the system bus; only the "
		             "private D-Bus socket will be available.");
		return FALSE;
	}

	priv->connection = dbus_g_connection_get_connection (priv->g_connection);
	dbus_connection_set_exit_on_disconnect (priv->connection, FALSE);

	priv->proxy = dbus_g_proxy_new_for_name (priv->g_connection,
	                                         DBUS_SERVICE_DBUS,
	                                         DBUS_PATH_DBUS,
	                                         DBUS_INTERFACE_DBUS);

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

	/* Pointless to request a name when we aren't connected to the bus */
	if (!priv->proxy)
		return FALSE;

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

static void
object_destroyed (NMDBusManager *self, gpointer object)
{
	g_hash_table_remove (NM_DBUS_MANAGER_GET_PRIVATE (self)->exported, object);
}

void
nm_dbus_manager_register_exported_type (NMDBusManager         *self,
                                        GType                  object_type,
                                        const DBusGObjectInfo *info)
{
	const char *properties_info, *dbus_name, *gobject_name, *tmp_access;

	dbus_g_object_type_install_info (object_type, info);
	if (!info->exported_properties)
		return;

	properties_info = info->exported_properties;
	while (*properties_info) {
		/* The format is: "interface\0DBusPropertyName\0gobject_property_name\0access\0" */
		dbus_name = strchr (properties_info, '\0') + 1;
		gobject_name = strchr (dbus_name, '\0') + 1;
		tmp_access = strchr (gobject_name, '\0') + 1;
		properties_info = strchr (tmp_access, '\0') + 1;

		/* Note that nm-properties-changed-signal takes advantage of the
		 * fact that @dbus_name and @gobject_name are static data that won't
		 * ever be freed.
		 */
		nm_properties_changed_signal_add_property (object_type, dbus_name, gobject_name);
	}
}

void
nm_dbus_manager_register_object (NMDBusManager *self,
                                 const char *path,
                                 gpointer object)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	DBusConnection *connection;

	g_assert (G_IS_OBJECT (object));

	if (g_hash_table_lookup (priv->exported, G_OBJECT (object)))
		g_return_if_reached ();

	g_hash_table_insert (priv->exported, G_OBJECT (object), g_strdup (path));
	g_object_weak_ref (G_OBJECT (object), (GWeakNotify) object_destroyed, self);

	if (priv->g_connection)
		dbus_g_connection_register_g_object (priv->g_connection, path, G_OBJECT (object));

	if (priv->priv_server) {
		g_hash_table_iter_init (&iter, priv->priv_server->connections);
		while (g_hash_table_iter_next (&iter, (gpointer) &connection, NULL)) {
			dbus_g_connection_register_g_object (dbus_connection_get_g_connection (connection),
			                                     path,
			                                     G_OBJECT (object));
		}
	}
}

void
nm_dbus_manager_unregister_object (NMDBusManager *self, gpointer object)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	DBusConnection *connection;

	g_assert (G_IS_OBJECT (object));

	if (!g_hash_table_lookup (priv->exported, G_OBJECT (object)))
		g_return_if_reached ();

	g_hash_table_remove (priv->exported, G_OBJECT (object));
	g_object_weak_unref (G_OBJECT (object), (GWeakNotify) object_destroyed, self);

	if (priv->g_connection)
		dbus_g_connection_unregister_g_object (priv->g_connection, G_OBJECT (object));

	if (priv->priv_server) {
		g_hash_table_iter_init (&iter, priv->priv_server->connections);
		while (g_hash_table_iter_next (&iter, (gpointer) &connection, NULL)) {
			dbus_g_connection_unregister_g_object (dbus_connection_get_g_connection (connection),
			                                       G_OBJECT (object));
		}
	}
}

/**
 * nm_dbus_manager_new_proxy:
 * @self: the #NMDBusManager
 * @context: the method call context this proxy should be created
 * @name: any name on the message bus
 * @path: name of the object instance to call methods on
 * @iface: name of the interface to call methods on
 *
 * Creates a new proxy for a name on a given bus.  Since the process which
 * called the D-Bus method could be coming from a private connection or the
 * system bus connection, differnet proxies must be created for each case.  This
 * function abstracts that.
 *
 * Returns: a #DBusGProxy capable of calling D-Bus methods of the calling process
 */
DBusGProxy *
nm_dbus_manager_new_proxy (NMDBusManager *self,
                           DBusGMethodInvocation *context,
                           const char *name,
                           const char *path,
                           const char *iface)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	DBusGConnection *connection;
	GSList *iter;
	const char *owner;

	connection = dbus_g_method_invocation_get_g_connection (context);
	g_assert (connection);

	/* Might be a private connection, for which we fake a sender */
	for (iter = priv->private_servers; iter; iter = g_slist_next (iter)) {
		PrivateServer *s = iter->data;

		owner = private_server_get_connection_owner (s, connection);
		if (owner) {
			g_assert_cmpstr (owner, ==, name);
			return dbus_g_proxy_new_for_peer (connection, path, iface);
		}
	}

	return dbus_g_proxy_new_for_name (connection, name, path, iface);
}

#if !HAVE_DBUS_GLIB_GMI_GET_CONNECTION
struct _HACKDBusGMethodInvocation {
  DBusGConnection *connection;
  /* ... */
};

DBusGConnection *
dbus_g_method_invocation_get_g_connection (DBusGMethodInvocation *context)
{
	/* Evil hack; this method exists in dbus-glib >= 101, but if we don't
	 * have that, emulate it.
	 */
	return ((struct _HACKDBusGMethodInvocation *) context)->connection;
}
#endif  /* HAVE_DBUS_GLIB_GMI_GET_CONNECTION */
