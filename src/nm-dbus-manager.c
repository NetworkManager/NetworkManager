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

#include "config.h"
#include "NetworkManager.h"
#include "nm-dbus-manager.h"
#include "nm-marshal.h"

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <string.h>
#include "nm-utils.h"

static gboolean nm_dbus_manager_init_bus (NMDBusManager *self);
static void nm_dbus_manager_cleanup (NMDBusManager *self);
static void free_signal_handler_data (gpointer data);
static void start_reconnection_timeout (NMDBusManager *self);

enum {
	PROP_0,
	PROP_MAIN_CONTEXT,
	PROP_DBUS_CONNECTION
};

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


typedef struct SignalHandlerData {
	NMDBusSignalHandlerFunc	func;
	char *					sender;
	gpointer				user_data;
	gboolean				enabled;
} SignalHandlerData;

typedef struct MethodHandlerData {
	NMDbusMethodList *	list;
	NMDBusManager *		self;
} MethodHandlerData;

struct _NMDBusManagerPrivate {
	DBusConnection *connection;
	GMainContext *  main_ctx;
	GSList *		msg_handlers;
	GHashTable *	signal_handlers;
	gboolean		started;
	gboolean		disposed;
};

NMDBusManager *
nm_dbus_manager_get (GMainContext *ctx)
{
	static NMDBusManager *singleton = NULL;
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;

	/* Ensure that if singleton is NULL, that ctx is non-NULL */
	g_return_val_if_fail (singleton ? TRUE : (ctx ? TRUE : FALSE), NULL);

	g_static_mutex_lock (&mutex);
	if (!singleton) {
		singleton = NM_DBUS_MANAGER (g_object_new (NM_TYPE_DBUS_MANAGER,
		                                           "main-context", ctx,
		                                           NULL));
		if (!nm_dbus_manager_init_bus (singleton))
			start_reconnection_timeout (singleton);
	} else {
		g_object_ref (singleton);
	}
	g_static_mutex_unlock (&mutex);

	g_assert (singleton);
	return singleton;
}

static void
nm_dbus_manager_init (NMDBusManager *self)
{
	self->priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	self->priv->signal_handlers = g_hash_table_new_full (g_str_hash,
	                                                     g_str_equal,
	                                                     g_free,
	                                                     free_signal_handler_data);
}

static void
nm_dbus_manager_set_property (GObject *object,
                              guint prop_id,
                              const GValue *value,
                              GParamSpec *pspec)
{
	NMDBusManager *self = NM_DBUS_MANAGER (object);

	switch (prop_id) {
		case PROP_MAIN_CONTEXT:
			if (!self->priv->main_ctx) {
				self->priv->main_ctx = g_value_get_pointer (value);
				g_main_context_ref (self->priv->main_ctx);
			} else {
				nm_warning ("already have a valid main context.");
			}
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static void
nm_dbus_manager_get_property (GObject *object,
                               guint prop_id,
                               GValue *value,
                               GParamSpec *pspec)
{
	NMDBusManager *self = NM_DBUS_MANAGER (object);

	switch (prop_id) {
		case PROP_DBUS_CONNECTION:
			g_value_set_pointer (value, self->priv->connection);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static void
nm_dbus_manager_dispose (GObject *object)
{
	NMDBusManager *self = NM_DBUS_MANAGER (object);

	if (self->priv->disposed)
		return;
	self->priv->disposed = TRUE;
}

static void
cleanup_handler_data (gpointer item, gpointer user_data)
{
	MethodHandlerData * data = (MethodHandlerData *) item;

	nm_dbus_method_list_unref (data->list);
	g_slice_free (MethodHandlerData, item);
}

static void
nm_dbus_manager_finalize (GObject *object)
{
	NMDBusManager *	self = NM_DBUS_MANAGER (object);

	g_return_if_fail (self->priv != NULL);

	nm_dbus_manager_cleanup (self);
	g_main_context_unref (self->priv->main_ctx);
	g_slist_foreach (self->priv->msg_handlers, cleanup_handler_data, NULL);
	g_slist_free (self->priv->msg_handlers);
	g_hash_table_destroy (self->priv->signal_handlers);

	G_OBJECT_CLASS (nm_dbus_manager_parent_class)->finalize (object);
}

static void
nm_dbus_manager_class_init (NMDBusManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = nm_dbus_manager_dispose;
	object_class->finalize = nm_dbus_manager_finalize;
	object_class->get_property = nm_dbus_manager_get_property;
	object_class->set_property = nm_dbus_manager_set_property;

	g_object_class_install_property (object_class,
	                                 PROP_MAIN_CONTEXT,
	                                 g_param_spec_pointer ("main-context",
	                                     "GMainContext",
	                                     "The mainloop context.",
	                                     G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY)
	                                );

	g_object_class_install_property (object_class,
	                                 PROP_DBUS_CONNECTION,
	                                 g_param_spec_pointer ("dbus-connection",
	                                     "DBusConnection",
	                                     "The application's dbus connection.",
	                                     G_PARAM_READABLE)
	                                );

	nm_dbus_manager_signals[DBUS_CONNECTION_CHANGED] =
		g_signal_new ("dbus-connection-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMDBusManagerClass, dbus_connection_changed),
		              NULL, NULL, nm_marshal_VOID__POINTER,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);
	klass->dbus_connection_changed = NULL;

	nm_dbus_manager_signals[NAME_OWNER_CHANGED] =
		g_signal_new ("name-owner-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMDBusManagerClass, name_owner_changed),
		              NULL, NULL, nm_marshal_VOID__POINTER_STRING_STRING_STRING,
		              G_TYPE_NONE, 4, G_TYPE_POINTER, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
	klass->name_owner_changed = NULL;

	g_type_class_add_private (klass, sizeof (NMDBusManagerPrivate));
}


/* Only cleanup a specific dbus connection, not all our private data */
static void
nm_dbus_manager_cleanup (NMDBusManager *self)
{
	if (self->priv->connection) {
		dbus_connection_close (self->priv->connection);
		self->priv->connection = NULL;
	}
	self->priv->started = FALSE;
}

static gboolean
nm_dbus_manager_reconnect (gpointer user_data)
{
	NMDBusManager *self = NM_DBUS_MANAGER (user_data);
	gboolean success = FALSE;

	g_assert (self != NULL);

	if (nm_dbus_manager_init_bus (self)) {
		if (nm_dbus_manager_start_service (self)) {
			nm_info ("reconnected to the system bus.");
			g_signal_emit (G_OBJECT (self), 
					nm_dbus_manager_signals[DBUS_CONNECTION_CHANGED],
					0, self->priv->connection);
			success = TRUE;
		}
	}

	if (!success) {
		nm_dbus_manager_cleanup (self);
	}

	/* Remove the source only if reconnection was successful */
	return success ? FALSE : TRUE;
}

static char *
get_match_for (const char *interface, const char *sender)
{
	return g_strdup_printf ("type='signal',interface='%s',sender='%s'",
	                        interface, sender);
}

static gboolean
add_match_helper (NMDBusManager *self,
                  const char *interface,
                  const char *sender)
{
	gboolean success = FALSE;
	DBusError error;
	char * match;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (interface != NULL, FALSE);
	g_return_val_if_fail (sender != NULL, FALSE);

	match = get_match_for (interface, sender);
	dbus_error_init (&error);
	dbus_bus_add_match (self->priv->connection, match, &error);
	if (dbus_error_is_set (&error)) {
		nm_warning ("failed to add signal match for '%s'.", interface);
		dbus_error_free (&error);
	} else {
		success = TRUE;
	}
	g_free (match);
	return success;
}

static void
start_reconnection_timeout (NMDBusManager *self)
{
	GSource * source;

	/* Schedule timeout for reconnection attempts */
	source = g_timeout_source_new (3000);
	g_source_set_callback (source,
	                       (GSourceFunc) nm_dbus_manager_reconnect,
	                       self,
	                       NULL);
	g_source_attach (source, self->priv->main_ctx);
	g_source_unref (source);
}

static DBusHandlerResult
nm_dbus_manager_signal_handler (DBusConnection *connection,
                                DBusMessage *message,
                                void *user_data)
{
	NMDBusManager *	self = NM_DBUS_MANAGER (user_data);
	gboolean		handled = FALSE;

	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (self != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (dbus_message_get_type (message) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (0) {
		const char * interface = dbus_message_get_interface (message);
		const char * path = dbus_message_get_path (message);
		const char * member = dbus_message_get_member (message);
		const char * sig = dbus_message_get_signature (message);
		nm_info ("(signal) iface: %s, path: %s, member: %s, sig: %s",
				interface, path, member, sig);
	}

	if (dbus_message_is_signal (message, DBUS_INTERFACE_DBUS, "NameOwnerChanged")) {
		gboolean success;
		const char * name;
		const char * old_owner;
		const char * new_owner;

		success = dbus_message_get_args (message, NULL,
		                                 DBUS_TYPE_STRING, &name,
		                                 DBUS_TYPE_STRING, &old_owner,
		                                 DBUS_TYPE_STRING, &new_owner,
		                                 DBUS_TYPE_INVALID);
		if (success) {
			SignalHandlerData * sig_data;
			gboolean			old_owner_good = (old_owner && strlen (old_owner));
			gboolean			new_owner_good = (new_owner && strlen (new_owner));

			sig_data = g_hash_table_lookup (self->priv->signal_handlers,
			                                name);

			if (!old_owner_good && new_owner_good) {
				/* Add any matches registered with us */
				if (sig_data) {
					sig_data->enabled = add_match_helper (self,
					                                      name,
					                                      sig_data->sender);
				}
			} else if (old_owner_good && !new_owner_good) {
				/* Mark any matches for services that have gone away as disabled. */
				if (sig_data)
					sig_data->enabled = FALSE;
			}

			g_signal_emit (G_OBJECT (self), 
					nm_dbus_manager_signals[NAME_OWNER_CHANGED],
					0, connection, name, old_owner, new_owner);
			handled = TRUE;
		}
	} else if (dbus_message_is_signal (message, DBUS_INTERFACE_LOCAL, "Disconnected")) {
		/* Clean up existing connection */
		nm_info ("disconnected by the system bus.");
		nm_dbus_manager_cleanup (self);
		g_signal_emit (G_OBJECT (self), 
				nm_dbus_manager_signals[DBUS_CONNECTION_CHANGED],
				0, NULL);

		start_reconnection_timeout (self);

		handled = TRUE;
	} else {
		SignalHandlerData *	cb_data;		
		const char *		interface;

		interface = dbus_message_get_interface (message);
		if (interface) {
			if ((cb_data = g_hash_table_lookup (self->priv->signal_handlers,
			                                    interface))) {
				handled = (*cb_data->func) (connection,
				                            message,
				                            cb_data->user_data);
			}
		}
	}

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}

char *
nm_dbus_manager_get_name_owner (NMDBusManager *self,
                                const char *name)
{
	DBusError		error;
	DBusMessage *	message;
	DBusMessage *	reply = NULL;
	char *		owner = NULL;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (name != NULL, NULL);

	message = dbus_message_new_method_call (DBUS_SERVICE_DBUS,
	                                        DBUS_PATH_DBUS,
	                                        DBUS_INTERFACE_DBUS,
	                                        "GetNameOwner");
	if (!message) {
		nm_warning ("Not enough memory for DBus message.");
		goto out;
	}

	dbus_message_append_args (message, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (self->priv->connection,
	                                                   message, 2000, &error);
	if (dbus_error_is_set (&error)) {
		nm_warning ("Did not get reply from DBus.  Message: %s", error.message);
		dbus_error_free (&error);
		goto out;
	}

	if (reply) {
		const char *tmp_name = NULL;
		if (dbus_message_get_args (reply, NULL, DBUS_TYPE_STRING,
		                           &tmp_name, DBUS_TYPE_INVALID))
			owner = g_strdup (tmp_name);
	}

out:
	if (reply)
		dbus_message_unref (reply);
	if (message)
		dbus_message_unref (message);
	return owner;
}

gboolean
nm_dbus_manager_name_has_owner (NMDBusManager *self,
                                const char *name)
{
	DBusError	error;
	gboolean	running = FALSE;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (name != NULL, FALSE);

	if (!self->priv->connection) {
		nm_warning ("Called when manager had no dbus connection.");
		return FALSE;
	}

	dbus_error_init (&error);
	running = dbus_bus_name_has_owner (self->priv->connection, name, &error);
	if (dbus_error_is_set (&error)) {
		running = FALSE;
		dbus_error_free (&error);
	}
	return running;
}

static DBusHandlerResult
nm_dbus_manager_message_handler (DBusConnection *connection,
                                 DBusMessage *message,
                                 void *user_data)
{
	MethodHandlerData *	data = (MethodHandlerData *) user_data;
	NMDBusManager *		self = data->self;
	NMDbusMethodList *	list = data->list;
	DBusObjectPathMessageFunction	custom_handler_func;
	gboolean			handled = FALSE;
	DBusMessage *		reply = NULL;
	void *				hdlr_user_data;

	g_return_val_if_fail (self != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (list != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	hdlr_user_data = nm_dbus_method_list_get_user_data (list);

	/* Try the method lists' custom handler first */
	custom_handler_func = nm_dbus_method_list_get_custom_handler_func (list);
	if (custom_handler_func) {
		handled = (*custom_handler_func) (connection, message, hdlr_user_data);
	} else {
		/* Generic handler for lists that don't specify a custom handler */
		handled = nm_dbus_method_list_dispatch (list, connection, message,
		                                        hdlr_user_data, &reply);
		if (reply) {
			dbus_connection_send (connection, reply, NULL);
			dbus_message_unref (reply);
		}
	}

	return handled ? DBUS_HANDLER_RESULT_HANDLED
	                 : DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static gboolean
nm_dbus_manager_init_bus (NMDBusManager *self)
{
	DBusError	error;
	gboolean	success = FALSE;

	g_return_val_if_fail (self->priv->main_ctx, FALSE);

	if (self->priv->connection) {
		nm_warning ("DBus Manager already has a valid connection.");
		return FALSE;
	}

	dbus_connection_set_change_sigpipe (TRUE);
	
	dbus_error_init (&error);
	self->priv->connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (dbus_error_is_set (&error)) {
		nm_warning ("Could not get the system bus.  Make sure "
		            "the message bus daemon is running!  Message: %s",
		            error.message);
		dbus_error_free (&error);
		goto out;
	}

	dbus_connection_set_exit_on_disconnect (self->priv->connection, FALSE);	
	dbus_connection_setup_with_g_main (self->priv->connection,
	                                   self->priv->main_ctx);

	if (!dbus_connection_add_filter (self->priv->connection,
	                                 nm_dbus_manager_signal_handler,
	                                 self,
	                                 NULL)) {
		nm_warning ("Could not register a dbus message filter.  The "
		            "NetworkManager dbus security policy may not be loaded. "
		            "Restart dbus?");
		goto out;
	}
	success = TRUE;

	/* Monitor DBus signals for service start/stop announcements */
	dbus_error_init (&error);
	dbus_bus_add_match (self->priv->connection,
				"type='signal',"
				"interface='" DBUS_INTERFACE_DBUS "',"
				"sender='" DBUS_SERVICE_DBUS "'",
				&error);
	if (dbus_error_is_set (&error)) {
		nm_warning ("Could not monitor DBus signals.  Message: %s",
		            error.message);
		dbus_error_free (&error);
		goto out;
	}
	success = TRUE;

out:
	if (!success)
		nm_dbus_manager_cleanup (self);
	return success;
}

static gboolean
nm_dbus_manager_register_method_handlers (NMDBusManager *self)
{
	gboolean success = FALSE;
	GSList * elt;

	g_return_val_if_fail (self != NULL, FALSE);

	for (elt = self->priv->msg_handlers; elt; elt = g_slist_next (elt)) {
		MethodHandlerData *		data = (MethodHandlerData *) elt->data;
		DBusObjectPathVTable	vtable = {NULL, &nm_dbus_manager_message_handler,
		                                  NULL, NULL, NULL, NULL};
		dbus_bool_t				ret = FALSE;
		const char *			path;

		if (!nm_dbus_method_list_get_path (data->list)) {
			nm_warning ("DBus message handler had no path.");
			continue;
		}

		/* If the method list object specifies a custom handler, use that
		 * instead of our default built-in one.
		 */
		path = nm_dbus_method_list_get_path (data->list);
		if (nm_dbus_method_list_get_is_fallback (data->list)) {
			ret = dbus_connection_register_fallback (self->priv->connection,
			                                         path, &vtable, data);
		} else {
			ret = dbus_connection_register_object_path (self->priv->connection,
			                                            path, &vtable, data);
		}

		if (ret == FALSE) {
			nm_warning ("Could not register DBus message handler for path %s.",
			            path);
			goto out;
		}
	}
	success = TRUE;

out:
	return success;
}

static void
register_signal_handler (gpointer key,
                         gpointer value,
                         gpointer user_data)
{
	NMDBusManager *self = NM_DBUS_MANAGER (user_data);
	SignalHandlerData *	cb_data = (SignalHandlerData *) value;

	if (nm_dbus_manager_name_has_owner (self, key))
		add_match_helper (self, key, cb_data->sender);
}

static gboolean
nm_dbus_manager_register_signal_handlers (NMDBusManager *self)
{
	g_return_val_if_fail (self != NULL, FALSE);

	g_hash_table_foreach (self->priv->signal_handlers,
	                      register_signal_handler,
	                      self);
	return TRUE;
}

/* Register our service on the bus; shouldn't be called until
 * all necessary message handlers have been registered, because
 * when we register on the bus, clients may start to call.
 */
gboolean
nm_dbus_manager_start_service (NMDBusManager *self)
{
	DBusError	error;
	gboolean	success = FALSE;
	int			flags, ret;

	g_return_val_if_fail (self != NULL, FALSE);

	if (self->priv->started) {
		nm_warning ("Service has already started.");
		return FALSE;
	}

	/* Register our method handlers */
	if (!nm_dbus_manager_register_method_handlers (self))
		goto out;

	/* And our signal handlers */
	if (!nm_dbus_manager_register_signal_handlers (self))
		goto out;

	dbus_error_init (&error);
#if (DBUS_VERSION_MAJOR == 0) && (DBUS_VERSION_MINOR >= 60)
	flags = DBUS_NAME_FLAG_DO_NOT_QUEUE;
#else
	flags = DBUS_NAME_FLAG_PROHIBIT_REPLACEMENT;
#endif
	ret = dbus_bus_request_name (self->priv->connection, NM_DBUS_SERVICE,
	                             flags, &error);
	if (dbus_error_is_set (&error)) {
		nm_warning ("Could not acquire the NetworkManager service.\n"
		            "  Message: '%s'", error.message);
		dbus_error_free (&error);
		goto out;
	}

	if (ret != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		nm_warning ("Could not acquire the NetworkManager service as it"
		            "is already taken.  Return: %d",
		            ret);
		goto out;
	}

	self->priv->started = TRUE;
	success = TRUE;

out:
	if (!success)
		nm_dbus_manager_cleanup (self);
	return success;
}

void
nm_dbus_manager_register_method_list (NMDBusManager *self,
                                      NMDbusMethodList *list)
{
	MethodHandlerData * data;

	g_return_if_fail (self != NULL);
	g_return_if_fail (list != NULL);

	if (self->priv->started) {
		nm_warning ("DBus Manager object already started!");
		return;
	}

	if (self->priv->connection == NULL) {
		nm_warning ("DBus Manager object not yet initialized!");
		return;
	}

	if (g_slist_find (self->priv->msg_handlers, list)) {
		nm_warning ("Handler already registered.");
		return;
	}

	data = g_slice_new0 (MethodHandlerData);
	if (!data) {
		nm_warning ("Not enough memory to register the handler.");
		return;
	}

	nm_dbus_method_list_ref (list);
	data->list = list;
	data->self = self;
	self->priv->msg_handlers = g_slist_append (self->priv->msg_handlers, data);	
}

static void
free_signal_handler_data (gpointer data)
{
	SignalHandlerData *	cb_data = (SignalHandlerData *) data;

	g_return_if_fail (cb_data != NULL);

	g_free (cb_data->sender);
	g_slice_free (SignalHandlerData, cb_data);
}

void
nm_dbus_manager_register_signal_handler (NMDBusManager *self,
                                         const char *interface,
                                         const char *sender,
                                         NMDBusSignalHandlerFunc callback,
                                         gpointer user_data)
{
	SignalHandlerData *	cb_data;

	g_return_if_fail (self != NULL);
	g_return_if_fail (interface != NULL);
	g_return_if_fail (callback != NULL);

	if (!(cb_data = g_slice_new0 (SignalHandlerData)))
		return;
	cb_data->sender = sender ? g_strdup (sender) : g_strdup (interface);
	cb_data->func = callback;
	cb_data->user_data = user_data;
	g_hash_table_insert (self->priv->signal_handlers,
	                     g_strdup (interface),
	                     cb_data);

	if (nm_dbus_manager_name_has_owner (self, cb_data->sender))
		cb_data->enabled = add_match_helper (self, interface, cb_data->sender);
}

void
nm_dbus_manager_remove_signal_handler (NMDBusManager *self,
                                       const char *interface)
{
	SignalHandlerData *	cb_data;
	DBusError error;
	char * match;

	g_return_if_fail (self != NULL);
	g_return_if_fail (interface != NULL);

	cb_data = g_hash_table_lookup (self->priv->signal_handlers, interface);
	if (!cb_data)
		return;

	if (cb_data->enabled == FALSE)
		goto out;
	if (nm_dbus_manager_name_has_owner (self, cb_data->sender))
		goto out;

	match = get_match_for (interface, cb_data->sender);
 	dbus_error_init (&error);
	dbus_bus_remove_match (self->priv->connection, match, &error);
	if (dbus_error_is_set (&error)) {
		nm_warning ("failed to remove signal match for '%s'.", interface);
		dbus_error_free (&error);
	}
	g_free (match);

out:
	g_hash_table_remove (self->priv->signal_handlers, interface);
}

DBusConnection *
nm_dbus_manager_get_dbus_connection (NMDBusManager *self)
{
	GValue value = {0,};

	g_return_val_if_fail (self != NULL, NULL);

	g_value_init (&value, G_TYPE_POINTER);
	g_object_get_property (G_OBJECT (self), "dbus-connection", &value);
	return g_value_get_pointer (&value);
}
