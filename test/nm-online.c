/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2006 - 2008 Novell, Inc.
 *
 */

/*
 * nm-online.c - Are we online?
 *
 * Return values:
 *
 * 	0	: already online or connection established within given timeout
 *	1	: offline or not online within given timeout
 *	2	: unspecified error
 *
 * Robert Love <rml@novell.com>
 */

#define PROGRESS_STEPS 15

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>

#include "NetworkManager.h"
#include "nm-glib-compat.h"

typedef struct 
{
	int value;
	double norm;
	gboolean quiet;
} Timeout;

static GMainLoop *loop;

static DBusHandlerResult dbus_filter (DBusConnection *connection G_GNUC_UNUSED,
				      DBusMessage *message,
				      void *user_data G_GNUC_UNUSED)
{
	NMState state;

	if (!dbus_message_is_signal (message, NM_DBUS_INTERFACE, "StateChanged"))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_UINT32, &state, DBUS_TYPE_INVALID))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (state == NM_STATE_CONNECTED)
		g_main_loop_quit (loop);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static NMState check_online (DBusConnection *connection)
{
	DBusMessage *message, *reply;
	DBusError error;
	dbus_uint32_t state;
	
	message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH,
						NM_DBUS_INTERFACE, "state");
	if (!message)
		exit (2);

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message,
							   -1, &error);
	dbus_message_unref (message);
	if (!reply) 
		return NM_STATE_UNKNOWN;

	if (!dbus_message_get_args (reply, NULL, DBUS_TYPE_UINT32, &state,
				    DBUS_TYPE_INVALID))
		exit (2);

	return state;
}

static gboolean handle_timeout (gpointer data)
{
	int i = PROGRESS_STEPS;
	Timeout *timeout = (Timeout *) data;

	if (!timeout->quiet) {
		g_print ("\rConnecting");
		for (; i > 0; i--)
			putchar ((timeout->value >= (i * timeout->norm)) ? ' ' : '.');
		if (timeout->value)
			g_print (" %4is", timeout->value);
		fflush (stdout);
	}

	timeout->value--;
	if (timeout->value < 0) {
		if (!timeout->quiet)
			g_print ("\n");
		exit (1);
	}

	return TRUE;
}

int main (int argc, char *argv[])
{
	DBusConnection *connection;
	DBusError error;
	NMState state;
	gint t_secs = -1;
	gboolean exit_no_nm = FALSE;
	gboolean quiet = FALSE;
	Timeout timeout;
	GOptionContext *opt_ctx = NULL;
	gboolean success;

	GOptionEntry options[] = {
		{"timeout", 't', 0, G_OPTION_ARG_INT, &t_secs, "Time to wait for a connection, in seconds (default is 30)", NULL},
		{"exit", 'x', 0, G_OPTION_ARG_NONE, &exit_no_nm, "Exit immediately if NetworkManager is not running or connecting", NULL},
		{"quiet", 'q', 0, G_OPTION_ARG_NONE, &quiet, "Don't print anything", NULL},
		{NULL}
	};

	opt_ctx = g_option_context_new ("");
	g_option_context_set_translation_domain (opt_ctx, "UTF-8");
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);

	g_option_context_set_summary (opt_ctx,
		"Waits for a successful connection in NetworkManager.");

	success = g_option_context_parse (opt_ctx, &argc, &argv, NULL);
	g_option_context_free (opt_ctx);

	if (!success) {
		g_warning ("Invalid option.  Please use --help to see a list of valid options.");
		return 2;
	}
	
	if (t_secs > -1)
		timeout.value = t_secs;
	else
		timeout.value = 30;
	if (timeout.value < 0 || timeout.value > 3600)  {
		g_warning ("Invalid option.  Please use --help to see a list of valid options.");
		return 2;
	}

	g_type_init ();
	loop = g_main_loop_new (NULL, FALSE);

	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (connection == NULL) {
		dbus_error_free (&error);
		return 2;
	}

	dbus_connection_setup_with_g_main (connection, NULL);

	if (!dbus_connection_add_filter (connection, dbus_filter, NULL, NULL))
		return 2;

	dbus_bus_add_match (connection,
			    "type='signal',"
			    "interface='" NM_DBUS_INTERFACE "',"
			    "sender='" NM_DBUS_SERVICE "',"
			    "path='" NM_DBUS_PATH "'", &error);
	if (dbus_error_is_set (&error)) {
		dbus_error_free (&error);
		return 2;
	}

	/* Check after we setup the filter to ensure that we cannot race. */
	state = check_online (connection);
	if (state == NM_STATE_CONNECTED)
		return 0;
	if (exit_no_nm && (state != NM_STATE_CONNECTING))
		return 1;

	if (timeout.value) {
		timeout.norm = (double) timeout.value / (double) PROGRESS_STEPS;
		g_timeout_add_seconds (1, handle_timeout, &timeout);
	}
	timeout.quiet = quiet;

	g_main_loop_run (loop);

	return 0;
}
