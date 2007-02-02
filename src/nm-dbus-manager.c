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

typedef struct SignalMatch {
	guint32  refcount;
	char *   interface;
	char *   sender;
	char *   owner;
	char *   match;
	gboolean enabled;
} SignalMatch;

typedef struct SignalHandlerData {
	guint32                 id;

	NMDBusSignalHandlerFunc func;
	gpointer                user_data;
	SignalMatch *           match;
} SignalHandlerData;

typedef struct MethodHandlerData {
	NMDbusMethodList *	list;
	NMDBusManager *		self;
} MethodHandlerData;

typedef struct {
	DBusConnection * connection;
	DBusGConnection *g_connection;
	DBusGProxy *     proxy;
	gboolean         started;

	GSList *         msg_handlers;

	GSList *         matches;
	GSList *         signal_handlers;
	guint32          sig_handler_id_counter;
} NMDBusManagerPrivate;


static gboolean nm_dbus_manager_init_bus (NMDBusManager *self);
static void nm_dbus_manager_cleanup (NMDBusManager *self);
static void free_signal_handler_data (SignalHandlerData * data, NMDBusManager * mgr);
static void start_reconnection_timeout (NMDBusManager *self);
static void signal_match_unref (SignalMatch * match, NMDBusManager * mgr);
static void signal_match_disable (SignalMatch * match);


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
cleanup_handler_data (gpointer item, gpointer user_data)
{
	MethodHandlerData * data = (MethodHandlerData *) item;

	nm_dbus_method_list_unref (data->list);
	memset (data, 0, sizeof (MethodHandlerData));
	g_slice_free (MethodHandlerData, data);
}

static void
free_signal_handler_helper (gpointer item,
                            gpointer user_data)
{
	NMDBusManager * mgr = (NMDBusManager *) user_data;
	SignalHandlerData * data = (SignalHandlerData *) item;

	free_signal_handler_data (data, mgr);
}

static void
signal_match_dispose_helper (gpointer item,
                             gpointer user_data)
{
	NMDBusManager * mgr = (NMDBusManager *) user_data;
	SignalMatch * match = (SignalMatch *) item;

	signal_match_unref (match, mgr);
}

static void
nm_dbus_manager_finalize (GObject *object)
{
	NMDBusManager *	self = NM_DBUS_MANAGER (object);
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (object);

	/* Must be done before the dbus connection is disposed */
	g_slist_foreach (priv->signal_handlers, free_signal_handler_helper, self);
	g_slist_free (priv->signal_handlers);

	g_slist_foreach (priv->matches, signal_match_dispose_helper, self);
	g_slist_free (priv->matches);

	nm_dbus_manager_cleanup (self);

	g_slist_foreach (priv->msg_handlers, cleanup_handler_data, NULL);
	g_slist_free (priv->msg_handlers);

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
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	if (priv->g_connection) {
		dbus_g_connection_unref (priv->g_connection);
		priv->g_connection = NULL;
		priv->connection = NULL;
	}

	if (priv->proxy) {
		g_object_unref (priv->proxy);
		priv->proxy = NULL;
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

static SignalMatch *
signal_match_new (const char *interface,
                  const char *sender)
{
	SignalMatch * match;

	g_return_val_if_fail (interface || sender, NULL);

	match = g_slice_new0 (SignalMatch);
	g_return_val_if_fail (match != NULL, NULL);
	match->refcount = 1;

	if (interface) {
		match->interface = g_strdup (interface);
		if (!match->interface)
			goto error;
	}

	if (sender) {
		match->sender = g_strdup (sender);
		if (!match->sender)
			goto error;
	}

	if (interface && sender) {
		match->match = g_strdup_printf ("type='signal',interface='%s',sender='%s'",
		                                interface, sender);
	} else if (interface && !sender) {
		match->match = g_strdup_printf ("type='signal',interface='%s'", interface);
	} else if (sender && !interface) {
		match->match = g_strdup_printf ("type='signal',sender='%s'", sender);
	}

	if (!match->match)
		goto error;

	return match;

error:
	signal_match_unref (match, NULL);
	return NULL;
}

static void
signal_match_ref (SignalMatch * match)
{
	g_return_if_fail (match != NULL);
	g_return_if_fail (match->refcount > 0);

	match->refcount++;
}

static void
signal_match_unref (SignalMatch * match,
                    NMDBusManager * mgr)
{
	DBusError error;

	g_return_if_fail (match != NULL);
	g_return_if_fail (match->refcount > 0);
	
	match->refcount--;
	if (match->refcount > 0)
		return;

	/* Remove the DBus bus match on dispose */
	if (mgr) {
	 	dbus_error_init (&error);
		dbus_bus_remove_match (NM_DBUS_MANAGER_GET_PRIVATE (mgr)->connection, match->match, &error);
		if (dbus_error_is_set (&error)) {
			nm_warning ("failed to remove signal match for sender '%s', "
			            "interface '%s'.",
			            match->sender ? match->sender : "(none)",
			            match->interface ? match->interface : "(none)");
			dbus_error_free (&error);
		}
	}
	match->enabled = FALSE;

	g_free (match->interface);
	g_free (match->sender);
	g_free (match->owner);
	g_free (match->match);
	memset (match, 0, sizeof (SignalMatch));
	g_slice_free (SignalMatch, match);
}

static SignalMatch *
find_signal_match (NMDBusManager *self,
                   const char *interface,
                   const char *sender)
{
	SignalMatch * found = NULL;
	GSList *      elt;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (interface || sender, NULL);

	for (elt = NM_DBUS_MANAGER_GET_PRIVATE (self)->matches; elt; elt = g_slist_next (elt)) {
		SignalMatch * match = (SignalMatch *) elt->data;

		if (!match)
			continue;

		if (interface && sender) {
			if (!match->interface || !match->sender)
				continue;
			if (!strcmp (match->interface, interface) && !strcmp (match->sender, sender)) {
				found = match;
				break;
			}
		} else if (interface && !sender) {
			if (!match->interface || match->sender)
				continue;
			if (!strcmp (match->interface, interface)) {
				found = match;
				break;
			}
		} else if (sender && !interface) {
			if (!match->sender || match->interface)
				continue;
			if (!strcmp (match->sender, sender)) {
				found = match;
				break;
			}
		}
	}

	return found;
}

static void
signal_match_enable (NMDBusManager * mgr,
                     SignalMatch * match,
                     const char * owner)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (mgr);
	DBusError error;

	g_return_if_fail (match != NULL);

	if (match->enabled == TRUE)
		return;

	if (!priv->connection)
		return;

	dbus_error_init (&error);
	dbus_bus_add_match (priv->connection, match->match, &error);
	if (dbus_error_is_set (&error)) {
		nm_warning ("failed to add signal match for sender '%s', "
		            "interface '%s'.",
		            match->sender ? match->sender : "(none)",
		            match->interface ? match->interface : "(none)");
		dbus_error_free (&error);
		signal_match_disable (match);
	} else {
		g_free (match->owner);
		if (owner) {
			match->owner = g_strdup (owner);
		} else if (match->sender) {
			match->owner = nm_dbus_manager_get_name_owner (mgr, match->sender);
			if (match->owner == NULL)
				nm_warning ("Couldn't get name owner for '%s'.", match->sender);
		}
		match->enabled = TRUE;
	}
}

static void
signal_match_disable (SignalMatch * match)
{
	g_return_if_fail (match != NULL);

	match->enabled = FALSE;
	g_free (match->owner);
	match->owner = NULL;
}

static void
start_reconnection_timeout (NMDBusManager *self)
{
	/* Schedule timeout for reconnection attempts */
	g_timeout_add (3000, nm_dbus_manager_reconnect, self);
}

static gboolean
dispatch_signal (NMDBusManager * self,
                 DBusMessage *   message)
{
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	gboolean            handled = FALSE;
	GSList *            elt;
	const char *        interface;
	const char *        sender;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (message != NULL, FALSE);

	interface = dbus_message_get_interface (message);
	if (!interface)
		return FALSE;

	sender = dbus_message_get_sender (message);

	g_return_val_if_fail (sender != NULL, FALSE);

	for (elt = priv->signal_handlers; elt; elt = g_slist_next (elt)) {
		gboolean            dispatch = FALSE;
		SignalHandlerData *	handler = (SignalHandlerData *) elt->data;
		SignalMatch *       match = handler->match;

		if (match->sender && !match->interface) {
			if (!strcmp (match->sender, sender)
			    || (match->owner && !strcmp (match->owner, sender)))
				dispatch = TRUE;
		} else if (match->interface && !match->sender) {
			if (!strcmp (match->interface, interface))
				dispatch = TRUE;
		} else if (match->interface && match->sender) {
			if (!strcmp (match->interface, interface)
			    && (!strcmp (match->sender, sender)
			        || !strcmp (match->owner, sender)))
				dispatch = TRUE;
		}
		if (!dispatch)
			continue;

		handled = (*handler->func) (priv->connection,
		                            message,
		                            handler->user_data);
		if (handled)
			break;
	}

	return handled;
}


static DBusHandlerResult
nm_dbus_manager_signal_handler (DBusConnection *connection,
                                DBusMessage *message,
                                void *user_data)
{
	NMDBusManager *	self = NM_DBUS_MANAGER (user_data);
	gboolean		handled;

	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (self != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	handled = dispatch_signal (self, message);

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
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

static void
proxy_name_owner_changed (DBusGProxy *proxy,
						  const char *name,
						  const char *old_owner,
						  const char *new_owner,
						  gpointer user_data)
{
	NMDBusManager *self = NM_DBUS_MANAGER (user_data);
	SignalMatch *match;
	gboolean old_owner_good = (old_owner && strlen (old_owner));
	gboolean new_owner_good = (new_owner && strlen (new_owner));

	match = find_signal_match (self, NULL, name);

	if (!old_owner_good && new_owner_good) {
		/* Add any matches for this owner */
		if (match) {
			signal_match_enable (self, match, new_owner);
		}
	} else if (old_owner_good && !new_owner_good) {
		/* Mark any matches for services that have gone away as disabled. */
		if (match) {
			signal_match_disable (match);
		}
	}

	g_signal_emit (G_OBJECT (self), 
				   nm_dbus_manager_signals[NAME_OWNER_CHANGED],
				   0,
				   NM_DBUS_MANAGER_GET_PRIVATE (self)->connection,
				   name, old_owner, new_owner);
}

static void
destroy_cb (DBusGProxy *proxy, gpointer user_data)
{
	NMDBusManager *self = NM_DBUS_MANAGER (user_data);

	/* Clean up existing connection */
	nm_info ("disconnected by the system bus.");
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
	DBusError	error;
	gboolean	success = FALSE;

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
		goto out;
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

	if (!dbus_connection_add_filter (priv->connection,
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
	dbus_bus_add_match (priv->connection,
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
	NMDBusManagerPrivate *priv = NM_DBUS_MANAGER_GET_PRIVATE (self);
	gboolean success = FALSE;
	GSList * elt;

	for (elt = priv->msg_handlers; elt; elt = g_slist_next (elt)) {
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
			ret = dbus_connection_register_fallback (priv->connection,
			                                         path, &vtable, data);
		} else {
			ret = dbus_connection_register_object_path (priv->connection,
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
	GSList *elt;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_DBUS_MANAGER (self), FALSE);

	priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	if (priv->started) {
		nm_warning ("Service has already started.");
		return FALSE;
	}

	/* Register our method handlers */
	if (!nm_dbus_manager_register_method_handlers (self))
		goto out;

	/* And our signal handlers */
	for (elt = priv->matches; elt; elt = g_slist_next (elt)) {
		signal_match_enable (self, (SignalMatch *) elt->data, NULL);
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
		nm_warning ("Could not acquire the NetworkManager service as it"
		            "is already taken.  Return: %d",
		            request_name_result);
		goto out;
	}

	priv->started = TRUE;

out:
	if (!priv->started)
		nm_dbus_manager_cleanup (self);

	return priv->started;
}

void
nm_dbus_manager_register_method_list (NMDBusManager *self,
                                      NMDbusMethodList *list)
{
	NMDBusManagerPrivate *priv;
	MethodHandlerData * data;

	g_return_if_fail (NM_IS_DBUS_MANAGER (self));
	g_return_if_fail (list != NULL);

	priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	if (priv->started) {
		nm_warning ("DBus Manager object already started!");
		return;
	}

	if (priv->connection == NULL) {
		nm_warning ("DBus Manager object not yet initialized!");
		return;
	}

	if (g_slist_find (priv->msg_handlers, list)) {
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
	priv->msg_handlers = g_slist_append (priv->msg_handlers, data);	
}

static void
free_signal_handler_data (SignalHandlerData * data,
                          NMDBusManager * mgr)
{
	g_return_if_fail (mgr != NULL);
	g_return_if_fail (data != NULL);

	if (data->match)
		signal_match_unref (data->match, mgr);

	memset (data, 0, sizeof (SignalHandlerData));
	g_slice_free (SignalHandlerData, data);
}

guint32
nm_dbus_manager_register_signal_handler (NMDBusManager *self,
                                         const char *interface,
                                         const char *sender,
                                         NMDBusSignalHandlerFunc callback,
                                         gpointer user_data)
{
	NMDBusManagerPrivate *priv;
	SignalHandlerData *	sig_handler;
	SignalMatch * match = NULL;

	g_return_val_if_fail (NM_IS_DBUS_MANAGER (self), 0);
	g_return_val_if_fail (callback != NULL, 0);

	/* One of interface or sender must be specified */
	g_return_val_if_fail (interface || sender, 0);

	priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	if (!(sig_handler = g_slice_new0 (SignalHandlerData))) {
		nm_warning ("Not enough memory for new signal handler.");
		return 0;
	}
	sig_handler->func = callback;
	sig_handler->user_data = user_data;

	/* Find or create the DBus bus match */
	match = find_signal_match (self, interface, sender);
	if (match != NULL) {
		sig_handler->match = match;
		signal_match_ref (match);		
	} else {
		sig_handler->match = signal_match_new (interface, sender);
		if (sig_handler->match == NULL) {
			nm_warning ("Could not create new signal match.");
			free_signal_handler_data (sig_handler, self);
			return 0;
		}
		priv->matches = g_slist_append (priv->matches,
										sig_handler->match);
	}

	signal_match_enable (self, sig_handler->match, NULL);

	priv->sig_handler_id_counter++;
	sig_handler->id = priv->sig_handler_id_counter;

	priv->signal_handlers = g_slist_append (priv->signal_handlers,
											sig_handler);

	return sig_handler->id;
}

void
nm_dbus_manager_remove_signal_handler (NMDBusManager *self,
                                       guint32 id)
{
	NMDBusManagerPrivate *priv;
	GSList * elt;
	GSList * found_elt = NULL;
	SignalHandlerData *	sig_handler = NULL;

	g_return_if_fail (NM_IS_DBUS_MANAGER (self));
	g_return_if_fail (id > 0);

	priv = NM_DBUS_MANAGER_GET_PRIVATE (self);

	for (elt = priv->signal_handlers; elt; elt = g_slist_next (elt)) {
		SignalHandlerData * handler = (SignalHandlerData *) elt->data;

		if (handler && (handler->id == id)) {
			sig_handler = handler;
			found_elt = elt;
			break;
		}
	}

	/* Not found */
	if (!sig_handler || !found_elt)
		return;

	/* Remove and free the signal handler */
	priv->signal_handlers = g_slist_remove_link (priv->signal_handlers,
												 found_elt);
	free_signal_handler_data (sig_handler, self);
	g_slist_free_1 (found_elt);
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
