/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2005 - 2008 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "NetworkManager.h"
#include "libnm_glib.h"

#define DBUS_NO_SERVICE_ERROR "org.freedesktop.DBus.Error.ServiceDoesNotExist"

struct libnm_glib_ctx
{
	unsigned char           check;

	GMainContext *          g_main_ctx;
	GMainLoop *             g_main_loop;
	DBusConnection  *       dbus_con;
	guint                   dbus_watcher;
	guint                   dbus_watch_interval;

	gboolean                thread_done;
	gboolean                thread_inited;
	GThread *               thread;

	GSList *                callbacks;
	GMutex *                callbacks_lock;
	guint                   callback_id_last;

	libnm_glib_state        nm_state;
};

typedef struct libnm_glib_callback
{
	guint                       id;
	GMainContext *              gmain_ctx;
	libnm_glib_ctx *            libnm_glib_ctx;
	libnm_glib_callback_func    func;
	gpointer                    user_data;
} libnm_glib_callback;

static void _libnm_glib_schedule_dbus_watcher (libnm_glib_ctx *ctx);
static DBusConnection * _libnm_glib_dbus_init (gpointer *user_data, GMainContext *context);
static void _libnm_glib_update_state (libnm_glib_ctx *ctx, NMState state);

static void
_libnm_glib_nm_state_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *reply;
	libnm_glib_ctx *ctx = (libnm_glib_ctx *) user_data;
	NMState nm_state;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (ctx != NULL);

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_ERROR)
	{
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);
		fprintf (stderr, "%s: dbus returned an error.\n  (%s) %s\n", __func__, err.name, err.message);
		dbus_error_free (&err);
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_UINT32, &nm_state, DBUS_TYPE_INVALID))
		_libnm_glib_update_state (ctx, nm_state);

	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
}

static void
_libnm_glib_get_nm_state (libnm_glib_ctx *ctx)
{
	DBusMessage *message;
	DBusPendingCall *pcall = NULL;

	g_return_if_fail (ctx != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH, NM_DBUS_INTERFACE, "state")))
	{
		dbus_connection_send_with_reply (ctx->dbus_con, message, &pcall, -1);
		if (pcall)
			dbus_pending_call_set_notify (pcall, _libnm_glib_nm_state_cb, ctx, NULL);
		dbus_message_unref (message);
	}
}

static gboolean
_libnm_glib_callback_helper (gpointer user_data)
{
	libnm_glib_callback *cb_data = (libnm_glib_callback *)user_data;

	g_return_val_if_fail (cb_data != NULL, FALSE);
	g_return_val_if_fail (cb_data->func != NULL, FALSE);
	g_return_val_if_fail (cb_data->libnm_glib_ctx != NULL, FALSE);

	(*(cb_data->func)) (cb_data->libnm_glib_ctx, cb_data->user_data);

	return FALSE;
}

static void
_libnm_glib_schedule_single_callback (libnm_glib_ctx *ctx,
                                      libnm_glib_callback *callback)
{
	GSource *source;

	g_return_if_fail (ctx != NULL);
	g_return_if_fail (callback != NULL);

	callback->libnm_glib_ctx = ctx;

	source = g_idle_source_new ();
	g_source_set_callback (source, _libnm_glib_callback_helper, callback, NULL);
	g_source_attach (source, callback->gmain_ctx);
	g_source_unref (source);
}

static void
_libnm_glib_unschedule_single_callback (libnm_glib_ctx *ctx,
                                        libnm_glib_callback *callback)
{
	GSource *source;

	g_return_if_fail (ctx != NULL);
	g_return_if_fail (callback != NULL);

	source = g_main_context_find_source_by_user_data (callback->gmain_ctx, callback);
	if (source)
		g_source_destroy (source);
}

static void
_libnm_glib_call_callbacks (libnm_glib_ctx *ctx)
{
	GSList *elem;

	g_return_if_fail (ctx != NULL);

	g_mutex_lock (ctx->callbacks_lock);
	for (elem = ctx->callbacks; elem; elem = g_slist_next (elem))
	{
		libnm_glib_callback *callback = (libnm_glib_callback *)(elem->data);
		if (callback)
			_libnm_glib_schedule_single_callback (ctx, callback);
	}
	g_mutex_unlock (ctx->callbacks_lock);
}

static void
_libnm_glib_update_state (libnm_glib_ctx *ctx, NMState state)
{
	libnm_glib_state old_state;

	g_return_if_fail (ctx != NULL);

	old_state = ctx->nm_state;
	switch (state) {
		case NM_STATE_CONNECTED_LOCAL:
		case NM_STATE_CONNECTED_SITE:
		case NM_STATE_CONNECTED_GLOBAL:
			ctx->nm_state = LIBNM_ACTIVE_NETWORK_CONNECTION;
			break;
		case NM_STATE_ASLEEP:
		case NM_STATE_CONNECTING:
		case NM_STATE_DISCONNECTED:
		case NM_STATE_DISCONNECTING:
			ctx->nm_state = LIBNM_NO_NETWORK_CONNECTION;
			break;
		case NM_STATE_UNKNOWN:
		default:
			ctx->nm_state = LIBNM_NO_NETWORKMANAGER;
			break;
	}

	if (old_state != ctx->nm_state)
		_libnm_glib_call_callbacks (ctx);
}

static DBusHandlerResult
_libnm_glib_dbus_filter (DBusConnection *connection,
                         DBusMessage *message,
                         void *user_data)
{
	libnm_glib_ctx *ctx = (libnm_glib_ctx *)user_data;
	gboolean handled = TRUE;
	DBusError error;

	g_return_val_if_fail (ctx != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	dbus_error_init (&error);
	if (dbus_message_is_signal (message, DBUS_INTERFACE_LOCAL, "Disconnected"))
	{
		/* Try to reactivate our connection to dbus on the next pass through the event loop */
		ctx->nm_state = LIBNM_NO_DBUS;
		dbus_connection_close (ctx->dbus_con);
		dbus_connection_unref (ctx->dbus_con);
		ctx->dbus_con = NULL;
		_libnm_glib_schedule_dbus_watcher (ctx);
	}
	else if (dbus_message_is_signal (message, DBUS_INTERFACE_DBUS, "NameOwnerChanged"))
	{
		/* New signal for dbus 0.23... */
		char *service;
		char *old_owner;
		char *new_owner;

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

				if (!old_owner_good && new_owner_good) /* Equivalent to old ServiceCreated signal */
					_libnm_glib_get_nm_state (ctx);
				else if (old_owner_good && !new_owner_good) /* Equivalent to old ServiceDeleted signal */
					ctx->nm_state = LIBNM_NO_NETWORKMANAGER;
			}
		}
	}
	else if (    dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNowActive")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNoLongerActive")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceActivating")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DevicesChanged"))
	{
		_libnm_glib_get_nm_state (ctx);
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "StateChanged"))
	{
		NMState state = NM_STATE_UNKNOWN;

		dbus_message_get_args (message, &error, DBUS_TYPE_UINT32, &state, DBUS_TYPE_INVALID);
		_libnm_glib_update_state (ctx, state);
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
static DBusConnection *
_libnm_glib_dbus_init (gpointer *user_data, GMainContext *context)
{
	DBusConnection *connection = NULL;
	DBusError error;

	dbus_error_init (&error);
	connection = dbus_bus_get_private (DBUS_BUS_SYSTEM, &error);
	if (dbus_error_is_set (&error))
	{
		fprintf (stderr, "%s: error, %s raised:\n %s\n\n", __func__, error.name, error.message);
		dbus_error_free (&error);
		return (NULL);
	}
	if (!connection)
		return NULL;

	if (!dbus_connection_add_filter (connection, _libnm_glib_dbus_filter, user_data, NULL))
		return (NULL);

	dbus_connection_set_exit_on_disconnect (connection, FALSE);
	dbus_connection_setup_with_g_main (connection, context);

	dbus_error_init (&error);
	dbus_bus_add_match (connection,
				"type='signal',"
				"interface='" DBUS_INTERFACE_DBUS "',"
				"sender='" DBUS_SERVICE_DBUS "'",
				&error);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);

	dbus_error_init (&error);
	dbus_bus_add_match (connection,
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
static gboolean
_libnm_glib_dbus_watcher (gpointer user_data)
{
	libnm_glib_ctx *ctx = (libnm_glib_ctx *)user_data;

	g_return_val_if_fail (ctx != NULL, FALSE);

	ctx->dbus_watcher = 0;

	if (!ctx->dbus_con)
		ctx->dbus_con = _libnm_glib_dbus_init ((gpointer)ctx, ctx->g_main_ctx);

	if (ctx->dbus_con)
	{
		/* Get NM's state right away after we reconnect */
		_libnm_glib_get_nm_state (ctx);
		ctx->dbus_watch_interval = 1000;
	}
	else
	{
		/* Wait 3 seconds longer each time we fail to reconnect to dbus,
		 * with a maximum wait of one minute.
		 */
		ctx->dbus_watch_interval = MIN(ctx->dbus_watch_interval + 3000, 60000);

		/* Reschule ourselves if we _still_ don't have a connection to dbus */
		_libnm_glib_schedule_dbus_watcher (ctx);
	}

	return FALSE;
}

/*
 * libnm_glib_schedule_dbus_watcher
 *
 * Schedule an idle handler in our main loop to repeatedly
 * attempt to re-activate the dbus connection until connected.
 *
 */
static void
_libnm_glib_schedule_dbus_watcher (libnm_glib_ctx *ctx)
{
	g_return_if_fail (ctx != NULL);

	if (ctx->dbus_watcher == 0)
	{
		GSource *source = g_timeout_source_new (ctx->dbus_watch_interval);
		g_source_set_callback (source, _libnm_glib_dbus_watcher, (gpointer) ctx, NULL);
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
static gpointer
_libnm_glib_dbus_worker (gpointer user_data)
{
	libnm_glib_ctx *ctx = (libnm_glib_ctx *)user_data;

	g_return_val_if_fail (ctx != NULL, NULL);

	/* If dbus isn't up yet, schedule an idle handler to check for dbus.
	 * We also need a way to reconnect to dbus if the connection ever goes
	 * down.  Should probably be done by a timeout polling dbus_connection_is_connected()
	 * or by getting connection status out of libdbus or something.
	 */
	if (!(ctx->dbus_con = _libnm_glib_dbus_init ((gpointer) ctx, ctx->g_main_ctx)))
		_libnm_glib_schedule_dbus_watcher (ctx);
	else
		_libnm_glib_get_nm_state (ctx);

	ctx->thread_inited = TRUE;
	g_main_loop_run (ctx->g_main_loop);
	ctx->thread_done = TRUE;

	return NULL;
}

static void
_libnm_glib_ctx_free (libnm_glib_ctx *ctx)
{
	g_return_if_fail (ctx != NULL);

	if (ctx->check == 0xDD)
	{
		fprintf (stderr, "%s: context %p already freed!\n", __func__, ctx);
		return;
	}

	if (ctx->g_main_ctx)
		g_main_context_unref (ctx->g_main_ctx);
	if (ctx->g_main_loop)
		g_main_loop_unref (ctx->g_main_loop);

	if (ctx->dbus_con)
	{
		dbus_connection_close (ctx->dbus_con);
		dbus_connection_unref (ctx->dbus_con);
		ctx->dbus_con = NULL;
	}

	if (ctx->callbacks_lock)
		g_mutex_free (ctx->callbacks_lock);

	g_slist_free_full (ctx->callbacks, g_free);

	if (ctx->thread)
		g_thread_join (ctx->thread);

	memset (ctx, 0, sizeof (libnm_glib_ctx));
	memset (&(ctx->check), 0xDD, sizeof (ctx->check));
	g_free (ctx);
}

static libnm_glib_ctx *
_libnm_glib_ctx_new (void)
{
	libnm_glib_ctx *ctx = g_malloc0 (sizeof (libnm_glib_ctx));

	if (!(ctx->g_main_ctx = g_main_context_new ()))
		goto error;
	if (!(ctx->g_main_loop = g_main_loop_new (ctx->g_main_ctx, FALSE)))
		goto error;
	if (!(ctx->callbacks_lock = g_mutex_new ()))
		goto error;
	ctx->dbus_watch_interval = 1000;

	return ctx;

error:
	_libnm_glib_ctx_free (ctx);
	return NULL;
}

libnm_glib_ctx *
libnm_glib_init (void)
{
	libnm_glib_ctx *ctx = NULL;

	if (!g_thread_supported ())
		g_thread_init (NULL);
	dbus_g_thread_init ();

	if (!(ctx = _libnm_glib_ctx_new ()))
		return NULL;

	ctx->thread = g_thread_create (_libnm_glib_dbus_worker, ctx, TRUE, NULL);
	if (!ctx->thread)
		goto error;

	/* Wait until initialization of the thread */
	while (!ctx->thread_inited)
		g_usleep (G_USEC_PER_SEC / 20);

	return ctx;

error:
	_libnm_glib_ctx_free (ctx);
	return NULL;
}

void
libnm_glib_shutdown (libnm_glib_ctx *ctx)
{
	g_return_if_fail (ctx != NULL);

	g_main_loop_quit (ctx->g_main_loop);
	while (!ctx->thread_done)
		g_usleep (G_USEC_PER_SEC / 20);

	_libnm_glib_ctx_free (ctx);
}

libnm_glib_state
libnm_glib_get_network_state (const libnm_glib_ctx *ctx)
{
	if (!ctx)
		return LIBNM_INVALID_CONTEXT;

	return ctx->nm_state;
}

guint
libnm_glib_register_callback (libnm_glib_ctx *ctx,
                              libnm_glib_callback_func func,
                              gpointer user_data,
                              GMainContext *g_main_ctx)
{
	libnm_glib_callback *callback = NULL;

	g_return_val_if_fail (ctx != NULL, 0);
	g_return_val_if_fail (func != NULL, 0);

	callback = g_malloc0 (sizeof (libnm_glib_callback));

	callback->id = ++ (ctx->callback_id_last);
	callback->func = func;
	callback->gmain_ctx = g_main_ctx;
	callback->libnm_glib_ctx = ctx;
	callback->user_data = user_data;

	g_mutex_lock (ctx->callbacks_lock);
	ctx->callbacks = g_slist_append (ctx->callbacks, callback);
	_libnm_glib_schedule_single_callback (ctx, callback);
	g_mutex_unlock (ctx->callbacks_lock);

	return (callback->id);
}

void
libnm_glib_unregister_callback (libnm_glib_ctx *ctx,
                                guint id)
{
	GSList *elem;

	g_return_if_fail (ctx != NULL);
	g_return_if_fail (id > 0);

	g_mutex_lock (ctx->callbacks_lock);
	elem = ctx->callbacks;
	while (elem)
	{
		libnm_glib_callback *callback = (libnm_glib_callback *)(elem->data);
		if (callback && (callback->id == id))
		{
			_libnm_glib_unschedule_single_callback (ctx, callback);
			ctx->callbacks = g_slist_remove_link (ctx->callbacks, elem);
			break;
		}

		elem = g_slist_next (elem);
	}
	g_mutex_unlock (ctx->callbacks_lock);
}
