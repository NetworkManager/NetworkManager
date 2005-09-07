/* libnm_glib -- Access NetworkManager information from applications
 *
 * Dan Williams <dcbw@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include "NetworkManager.h"
#include "libnm_glib.h"

#define	DBUS_NO_SERVICE_ERROR			"org.freedesktop.DBus.Error.ServiceDoesNotExist"

struct libnm_glib_ctx
{
	unsigned char		check;

	GMainContext *		g_main_ctx;
	GMainLoop *		g_main_loop;
	DBusConnection	*	dbus_con;
	guint			dbus_watcher;
	gboolean			thread_done;
	gboolean			thread_inited;

	GSList *			callbacks;
	GMutex *			callbacks_lock;
	gint				callback_id_last;

	libnm_glib_state	nm_state;
};

typedef struct libnm_glib_callback
{
	gint					id;
	GMainContext *			gmain_ctx;
	libnm_glib_ctx *		libnm_glib_ctx;
	libnm_glib_callback_func	func;
	gpointer				user_data;
} libnm_glib_callback;


static void libnm_glib_schedule_dbus_watcher (libnm_glib_ctx *ctx);
static DBusConnection * libnm_glib_dbus_init (gpointer *user_data, GMainContext *context);



static NMState libnm_glib_get_nm_state (DBusConnection *con)
{
	DBusMessage *	message;
	DBusMessage *	reply;
	DBusError		error;
	NMState		state = NM_STATE_UNKNOWN;

	g_return_val_if_fail (con != NULL, NM_STATE_UNKNOWN);

	if (!(message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "state")))
	{
		fprintf (stderr, "libnm_glib_get_nm_state(): Couldn't allocate the dbus message\n");
		return NM_STATE_UNKNOWN;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (con, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "libnm_glib_get_nm_state(): %s raised:\n %s\n\n", error.name, error.message);
		goto out;
	}

	if (!reply)
	{
		fprintf (stderr, "libnm_glib_get_nm_state(): dbus reply message was NULL\n" );
		goto out;
	}
	
	dbus_error_init (&error);
	if (!(dbus_message_get_args (reply, &error, DBUS_TYPE_UINT32, &state, DBUS_TYPE_INVALID)))
		fprintf (stderr, "libnm_glib_get_nm_state(): error while getting args: name='%s' message='%s'\n", error.name, error.message);
	dbus_message_unref (reply);

out:
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	return state;
}


static gboolean libnm_glib_callback_helper (gpointer user_data)
{
	libnm_glib_callback	*cb_data = (libnm_glib_callback *)user_data;

	g_return_val_if_fail (cb_data != NULL, FALSE);
	g_return_val_if_fail (cb_data->func != NULL, FALSE);
	g_return_val_if_fail (cb_data->libnm_glib_ctx != NULL, FALSE);

	(*(cb_data->func)) (cb_data->libnm_glib_ctx, cb_data->user_data);

	return FALSE; /* never reschedule ourselves */
}

static void libnm_glib_schedule_single_callback (libnm_glib_ctx *ctx, libnm_glib_callback *callback)
{
	GSource				*source;

	g_return_if_fail (ctx != NULL);
	g_return_if_fail (callback != NULL);

	callback->libnm_glib_ctx = ctx;

	source = g_idle_source_new ();
	g_source_set_callback (source, libnm_glib_callback_helper, callback, NULL);
	g_source_attach (source, callback->gmain_ctx);
	g_source_unref (source);
}


static void libnm_glib_call_callbacks (libnm_glib_ctx *ctx)
{
	GSList	*elem;

	g_return_if_fail (ctx != NULL);

	g_mutex_lock (ctx->callbacks_lock);
	for (elem = ctx->callbacks; elem; elem = g_slist_next (elem))
	{
		libnm_glib_callback *callback = (libnm_glib_callback *)(elem->data);
		if (callback)
			libnm_glib_schedule_single_callback (ctx, callback);
	}
	g_mutex_unlock (ctx->callbacks_lock);
}


static void libnm_glib_update_state (libnm_glib_ctx *ctx, NMState state)
{
	libnm_glib_state	old_state;

	g_return_if_fail (ctx != NULL);

	old_state = ctx->nm_state;
	switch (state)
	{
		case NM_STATE_CONNECTED:
			ctx->nm_state = LIBNM_ACTIVE_NETWORK_CONNECTION;
			break;

		case NM_STATE_ASLEEP:
		case NM_STATE_CONNECTING:
		case NM_STATE_DISCONNECTED:
			ctx->nm_state = LIBNM_NO_NETWORK_CONNECTION;
			break;

		case NM_STATE_UNKNOWN:
		default:
			ctx->nm_state = LIBNM_NO_NETWORKMANAGER;
			break;
	}

	if (old_state != ctx->nm_state)
		libnm_glib_call_callbacks (ctx);
}


static DBusHandlerResult libnm_glib_dbus_filter (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	libnm_glib_ctx		*ctx = (libnm_glib_ctx *)user_data;
	gboolean		 handled = TRUE;
	DBusError	 	 error;

	g_return_val_if_fail (ctx != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	dbus_error_init (&error);
	if (dbus_message_is_signal (message, DBUS_INTERFACE_LOCAL, "Disconnected"))
	{
		/* Try to reactivate our connection to dbus on the next pass through the event loop */
		ctx->nm_state = LIBNM_NO_DBUS;
		dbus_connection_disconnect (ctx->dbus_con);
		libnm_glib_schedule_dbus_watcher (ctx);
	}
	else if (dbus_message_is_signal (message, DBUS_INTERFACE_DBUS, "NameOwnerChanged"))
	{
		/* New signal for dbus 0.23... */
		char 	*service;
		char		*old_owner;
		char		*new_owner;

		if (    dbus_message_get_args (message, &error,
									DBUS_TYPE_STRING, &service,
									DBUS_TYPE_STRING, &old_owner,
									DBUS_TYPE_STRING, &new_owner,
									DBUS_TYPE_INVALID))
		{
			if (strcmp (service, NM_DBUS_SERVICE) == 0)
			{
				gboolean old_owner_good = (old_owner && (strlen (old_owner) > 0));
				gboolean new_owner_good = (new_owner && (strlen (new_owner) > 0));

				if (!old_owner_good && new_owner_good)	/* Equivalent to old ServiceCreated signal */
					libnm_glib_update_state (ctx, libnm_glib_get_nm_state (ctx->dbus_con));
				else if (old_owner_good && !new_owner_good)	/* Equivalent to old ServiceDeleted signal */
					ctx->nm_state = LIBNM_NO_NETWORKMANAGER;
			}
		}
	}
	else if (    dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNowActive")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNoLongerActive")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceActivating")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DevicesChanged"))
	{
		libnm_glib_update_state (ctx, libnm_glib_get_nm_state (ctx->dbus_con));
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, NM_DBUS_SIGNAL_STATE_CHANGE))
	{
		NMState	state = NM_STATE_UNKNOWN;

		dbus_message_get_args (message, &error, DBUS_TYPE_UINT32, &state, DBUS_TYPE_INVALID);
		libnm_glib_update_state (ctx, state);
	}
	else
		handled = FALSE;

	if (dbus_error_is_set (&error))
		dbus_error_free (&error);

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * libnm_glib_dbus_init
 *
 * Initialize a connection to dbus and set up our callbacks.
 *
 */
static DBusConnection * libnm_glib_dbus_init (gpointer *user_data, GMainContext *context)
{
	DBusConnection	*connection = NULL;
	DBusError		 error;

	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "libnm: error, %s raised:\n %s\n\n", error.name, error.message);
		dbus_error_free (&error);
		return (NULL);
	}
	if (!connection)
		return NULL;

	if (!dbus_connection_add_filter (connection, libnm_glib_dbus_filter, user_data, NULL))
		return (NULL);

	dbus_connection_set_exit_on_disconnect (connection, FALSE);
	dbus_connection_setup_with_g_main (connection, context);

	dbus_error_init (&error);
	dbus_bus_add_match(connection,
				"type='signal',"
				"interface='" DBUS_INTERFACE_DBUS "',"
				"sender='" DBUS_SERVICE_DBUS "'",
				&error);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);

	dbus_error_init (&error);
	dbus_bus_add_match(connection,
				"type='signal',"
				"interface='" NM_DBUS_INTERFACE "',"
				"path='" NM_DBUS_PATH "',"
				"sender='" NM_DBUS_SERVICE "'",
				&error);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);

	return (connection);
}


/*
 * libnm_glib_dbus_watcher
 *
 * Repeatedly try to re-activate the connection to dbus.
 *
 */
static gboolean libnm_glib_dbus_watcher (gpointer user_data)
{
	libnm_glib_ctx	*ctx = (libnm_glib_ctx *)user_data;

	g_return_val_if_fail (ctx != NULL, FALSE);

	if (!ctx->dbus_con)
		ctx->dbus_con = libnm_glib_dbus_init ((gpointer)ctx, ctx->g_main_ctx);

	if (ctx->dbus_con)
		return (FALSE);	/* Don't reschedule ourselves if we have a connection to dbus */

	/* Reschule ourselves if we _still_ don't have a connection to dbus */
	return (TRUE);
}


/*
 * libnm_glib_schedule_dbus_watcher
 *
 * Schedule an idle handler in our main loop to repeatedly
 * attempt to re-activate the dbus connection until connected.
 *
 */
static void libnm_glib_schedule_dbus_watcher (libnm_glib_ctx *ctx)
{
	g_return_if_fail (ctx != NULL);

	if (ctx->dbus_watcher == 0)
	{
		GSource	*source = g_idle_source_new ();
		g_source_set_callback (source, libnm_glib_dbus_watcher, (gpointer)ctx, NULL);
		ctx->dbus_watcher = g_source_attach (source, ctx->g_main_ctx);
		g_source_unref (source);
	}
}


/*
 * libnm_glib_dbus_worker
 *
 * Main thread for libnm
 *
 */
static gpointer libnm_glib_dbus_worker (gpointer user_data)
{
	libnm_glib_ctx	*ctx = (libnm_glib_ctx *)user_data;

	g_return_val_if_fail (ctx != NULL, NULL);

	/* If dbus isn't up yet, schedule an idle handler to check for dbus.
	 * We also need a way to reconnect to dbus if the connection ever goes
	 * down.  Should probably be done by a timeout polling dbus_connection_is_connected()
	 * or by getting connection status out of libdbus or something.
	 */
	if (!ctx->dbus_con)
		libnm_glib_schedule_dbus_watcher (ctx);
	else
	{
		/* Get initial status */
		libnm_glib_update_state (ctx, libnm_glib_get_nm_state (ctx->dbus_con));
	}

	ctx->thread_inited = TRUE;
	g_main_loop_run (ctx->g_main_loop);
	ctx->thread_done = TRUE;

	return NULL;
}


static void libnm_glib_ctx_free (libnm_glib_ctx *ctx)
{
	g_return_if_fail (ctx != NULL);

	if (ctx->check == 0xDD)
	{
		fprintf (stderr, "libnm_glib_ctx_free(): context %p already freed!\n", ctx);
		return;
	}

	if (ctx->g_main_ctx)
		g_main_context_unref (ctx->g_main_ctx);
	if (ctx->g_main_loop)
		g_main_loop_unref (ctx->g_main_loop);

	if (ctx->dbus_con)
		dbus_connection_disconnect (ctx->dbus_con);

	if (ctx->callbacks_lock)
		g_mutex_free (ctx->callbacks_lock);

	g_slist_foreach (ctx->callbacks, (GFunc)g_free, NULL);
	g_slist_free (ctx->callbacks);

	memset (ctx, 0, sizeof (libnm_glib_ctx));
	memset (&(ctx->check), 0xDD, sizeof (ctx->check));
	g_free (ctx);
}


static libnm_glib_ctx *libnm_glib_ctx_new (void)
{
	libnm_glib_ctx *ctx = g_malloc0 (sizeof (libnm_glib_ctx));

	if (!(ctx->g_main_ctx = g_main_context_new ()))
		goto error;
	if (!(ctx->g_main_loop = g_main_loop_new (ctx->g_main_ctx, FALSE)))
		goto error;
	if (!(ctx->callbacks_lock = g_mutex_new ()))
		goto error;

success:
	return ctx;

error:
	libnm_glib_ctx_free (ctx);
	return NULL;
}


libnm_glib_ctx *libnm_glib_init (void)
{
	GError	*error = NULL;
	libnm_glib_ctx	*ctx = NULL;

	g_type_init ();
	if (!g_thread_supported ())
		g_thread_init (NULL);
	dbus_g_thread_init ();

	ctx = libnm_glib_ctx_new();
	if (!ctx)
		return NULL;

	/* We don't care if dbus isn't around yet, we keep checking for it and
	 * intialize our connection when it comes up.
	 */
	ctx->dbus_con = libnm_glib_dbus_init ((gpointer)ctx, ctx->g_main_ctx);
	if (ctx->dbus_con)
		libnm_glib_update_state (ctx, libnm_glib_get_nm_state (ctx->dbus_con));

	if (!g_thread_create (libnm_glib_dbus_worker, ctx, FALSE, &error))
	{
		if (error)
			g_error_free (error);
		goto error;	
	}

	/* Wait until initialization of the thread */
	while (!ctx->thread_inited)
		g_usleep (G_USEC_PER_SEC / 2);

success:
	return ctx;

error:
	libnm_glib_ctx_free (ctx);
	return NULL;
}


void libnm_glib_shutdown (libnm_glib_ctx *ctx)
{
	g_return_if_fail (ctx != NULL);

	g_main_loop_quit (ctx->g_main_loop);
	while (!(ctx->thread_done))
		g_usleep (G_USEC_PER_SEC / 2);

	libnm_glib_ctx_free (ctx);
}


libnm_glib_state libnm_glib_get_network_state (const libnm_glib_ctx *ctx)
{
	if (!ctx)
		return LIBNM_INVALID_CONTEXT;

	return ctx->nm_state;
}


gint libnm_glib_register_callback	(libnm_glib_ctx *ctx, libnm_glib_callback_func func, gpointer user_data, GMainContext *g_main_ctx)
{
	libnm_glib_callback		*callback = NULL;

	g_return_val_if_fail (ctx != NULL, -1);
	g_return_val_if_fail (func != NULL, -1);
	
	callback = g_malloc0 (sizeof (libnm_glib_callback));

	callback->id = ctx->callback_id_last++;
	callback->func = func;
	callback->gmain_ctx = g_main_ctx;
	callback->libnm_glib_ctx = ctx;
	callback->user_data = user_data;

	g_mutex_lock (ctx->callbacks_lock);
	ctx->callbacks = g_slist_append (ctx->callbacks, callback);
	libnm_glib_schedule_single_callback (ctx, callback);
	g_mutex_unlock (ctx->callbacks_lock);

	return (callback->id);
}


void libnm_glib_unregister_callback (libnm_glib_ctx *ctx, gint id)
{
	GSList *elem;

	g_return_if_fail (ctx != NULL);
	g_return_if_fail (id < 0);

	g_mutex_lock (ctx->callbacks_lock);
	elem = ctx->callbacks;
	while (elem)
	{
		libnm_glib_callback *callback = (libnm_glib_callback *)(elem->data);
		if (callback && (callback->id == id))
		{
			ctx->callbacks = g_slist_remove_link (ctx->callbacks, elem);
			break;
		}

		elem = g_slist_next (elem);
	}
	g_mutex_unlock (ctx->callbacks_lock);
}
