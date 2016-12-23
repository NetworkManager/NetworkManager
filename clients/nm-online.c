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
 * Copyright (C) 2008 - 2014 Red Hat, Inc.
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

#include "nm-default.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <locale.h>

#include "NetworkManager.h"

#define PROGRESS_STEPS 15
#define WAIT_STARTUP_TAG "wait-startup"

typedef struct
{
	GMainLoop *loop;
	NMClient *client;
	gboolean exit_no_nm;
	gboolean wait_startup;
	gint64 start_timestamp_ms;
	gint64 end_timestamp_ms;
	gint64 progress_step_duration;
	gboolean quiet;
	guint retval;
} OnlineData;

static void
quit_if_connected (OnlineData *data)
{
	NMState state;

	state = nm_client_get_state (data->client);
	if (!nm_client_get_nm_running (data->client)) {
		if (data->exit_no_nm) {
			data->retval = 1;
			g_main_loop_quit (data->loop);
		}
	} else if (data->wait_startup) {
		if (!nm_client_get_startup (data->client)) {
			data->retval = 0;
			g_main_loop_quit (data->loop);
		}
	} else {
		if (   state == NM_STATE_CONNECTED_LOCAL
		    || state == NM_STATE_CONNECTED_SITE
		    || state == NM_STATE_CONNECTED_GLOBAL) {
			data->retval = 0;
			g_main_loop_quit (data->loop);
		}
	}
	if (data->exit_no_nm && (state != NM_STATE_CONNECTING)) {
		data->retval = 1;
		g_main_loop_quit (data->loop);
	}
}

static void
client_properties_changed (GObject *object,
                           GParamSpec *pspec,
                           gpointer user_data)
{
	OnlineData *data = user_data;
	quit_if_connected (data);
}

static gboolean
handle_timeout (gpointer user_data)
{
	const OnlineData *data = user_data;
	const gint64 now = g_get_monotonic_time () / (G_USEC_PER_SEC / 1000);
	gint64 remaining_ms = data->end_timestamp_ms - now;
	const gint64 elapsed_ms = now - data->start_timestamp_ms;
	int progress_next_step_i = 0;

	if (!data->quiet) {
		int i;

		/* calculate the next step (not the current): floor()+1 */
		progress_next_step_i = (elapsed_ms / data->progress_step_duration) + 1;
		progress_next_step_i = MIN (progress_next_step_i, PROGRESS_STEPS);

		g_print ("\r%s", _("Connecting"));
		for (i = 0; i < PROGRESS_STEPS; i++)
			putchar (i < progress_next_step_i ? '.' : ' ');
		g_print (" %4lds", (long) (MAX (0, remaining_ms) / 1000));
		fflush (stdout);
	}

	if (remaining_ms <= 3) {
		if (!data->quiet)
			g_print ("\n");
		exit (1);
	}

	if (!data->quiet) {
		gint64 rem;

		/* synchronize the timeout with the ticking of the seconds. */
		rem = remaining_ms % 1000;
		if (rem <= 3)
			rem = rem + G_USEC_PER_SEC;
		rem = rem + 10; /* add small offset to awake a bit after the second ticks */
		if (remaining_ms > rem)
			remaining_ms = rem;

		/* synchronize the timeout with the steps of the progress bar. */
		rem = (progress_next_step_i * data->progress_step_duration) - elapsed_ms;
		if (rem <= 3)
			rem = rem + data->progress_step_duration;
		rem = rem + 10; /* add small offset to awake a bit after the time out */
		if (remaining_ms > rem)
			remaining_ms = rem;
	}

	g_timeout_add (remaining_ms, handle_timeout, user_data);
	return G_SOURCE_REMOVE;
}

static void
got_client (GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	OnlineData *data = user_data;
	GError *error = NULL;

	data->client = nm_client_new_finish (res, &error);
	if (!data->client) {
		g_printerr (_("Error: Could not create NMClient object: %s."),
		            error->message);
		g_error_free (error);
		data->retval = 1;
		g_main_loop_quit (data->loop);
	}

	g_signal_connect (data->client, "notify",
	                  G_CALLBACK (client_properties_changed), user_data);
	quit_if_connected (data);
}

int
main (int argc, char *argv[])
{
	OnlineData data = { 0, };
	int t_secs = 30;
	GOptionContext *opt_ctx = NULL;
	gboolean success;
	gint64 remaining_ms;

	GOptionEntry options[] = {
		{"timeout", 't', 0, G_OPTION_ARG_INT, &t_secs, N_("Time to wait for a connection, in seconds (without the option, default value is 30)"), "<timeout>"},
		{"exit", 'x', 0, G_OPTION_ARG_NONE, &data.exit_no_nm, N_("Exit immediately if NetworkManager is not running or connecting"), NULL},
		{"quiet", 'q', 0, G_OPTION_ARG_NONE, &data.quiet, N_("Don't print anything"), NULL},
		{"wait-for-startup", 's', 0, G_OPTION_ARG_NONE, &data.wait_startup, N_("Wait for NetworkManager startup instead of a connection"), NULL},
		{NULL}
	};

	data.start_timestamp_ms = g_get_monotonic_time () / (G_USEC_PER_SEC / 1000);

	/* Set locale to be able to use environment variables */
	setlocale (LC_ALL, "");

	bindtextdomain (GETTEXT_PACKAGE, NMLOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_translation_domain (opt_ctx, GETTEXT_PACKAGE);
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);

	g_option_context_set_summary (opt_ctx,
	                              _("Waits for NetworkManager to finish activating startup network connections."));

	success = g_option_context_parse (opt_ctx, &argc, &argv, NULL);
	g_option_context_free (opt_ctx);

	if (!success) {
		g_printerr ("%s: %s\n", argv[0],
		            _("Invalid option.  Please use --help to see a list of valid options."));
		return 2;
	}

	if (t_secs < 0 || t_secs > 3600)  {
		g_printerr ("%s: %s\n", argv[0],
		            _("Invalid option.  Please use --help to see a list of valid options."));
		return 2;
	}
	nm_g_type_init ();

	data.loop = g_main_loop_new (NULL, FALSE);

	remaining_ms = t_secs * 1000;
	data.end_timestamp_ms = data.start_timestamp_ms + remaining_ms;
	data.progress_step_duration = (data.end_timestamp_ms - data.start_timestamp_ms + PROGRESS_STEPS/2) / PROGRESS_STEPS;

	g_timeout_add (data.quiet ? remaining_ms : 0, handle_timeout, &data);
	nm_client_new_async (NULL, got_client, &data);

	g_main_loop_run (data.loop);
	g_main_loop_unref (data.loop);
	if (data.client)
		g_object_unref (data.client);

	return data.retval;
}
