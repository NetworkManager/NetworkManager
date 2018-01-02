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
 * 0: already online or connection established within given timeout
 * 1: offline or not online within given timeout
 * 2: unspecified error
 *
 * Robert Love <rml@novell.com>
 */

#include "nm-default.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <locale.h>

#define PROGRESS_STEPS 15

#define EXIT_FAILURE_OFFLINE     1
#define EXIT_FAILURE_ERROR       2
#define EXIT_FAILURE_LIBNM_BUG   42
#define EXIT_FAILURE_UNSPECIFIED 43

typedef struct
{
	GMainLoop *loop;
	NMClient *client;
	GCancellable *client_new_cancellable;
	guint client_new_timeout_id;
	guint handle_timeout_id;
	gulong client_notify_id;
	gboolean exit_no_nm;
	gboolean wait_startup;
	gboolean quiet;
	gint64 start_timestamp_ms;
	gint64 end_timestamp_ms;
	gint64 progress_step_duration;
	int retval;
} OnlineData;

static gint64
_now_ms (void)
{
	return g_get_monotonic_time () / (G_USEC_PER_SEC / 1000);
}

static void
_return (OnlineData *data, int retval)
{
	nm_assert (data);
	nm_assert (data->retval == EXIT_FAILURE_UNSPECIFIED);

	data->retval = retval;
	nm_clear_g_signal_handler (data->client, &data->client_notify_id);
	g_main_loop_quit (data->loop);
}

static void
_print_progress (int progress_next_step_i, gint64 remaining_ms, int success)
{
	int i, j;

	j = progress_next_step_i < 0 ? PROGRESS_STEPS : progress_next_step_i;

	g_print ("\r%s", _("Connecting"));
	for (i = 0; i < PROGRESS_STEPS; i++)
		putchar (i < j ? '.' : ' ');
	g_print (" %4lds", (long) (MAX (0, remaining_ms + 999) / 1000));
	if (success >= 0)
		g_print (" [%sline]\n", success ? "on" : "off");
	fflush (stdout);
}

static gboolean
quit_if_connected (OnlineData *data)
{
	NMState state;

	state = nm_client_get_state (data->client);
	if (!nm_client_get_nm_running (data->client)) {
		if (data->exit_no_nm) {
			_return (data, EXIT_FAILURE_OFFLINE);
			return TRUE;
		}
	} else if (data->wait_startup) {
		if (!nm_client_get_startup (data->client)) {
			_return (data, EXIT_SUCCESS);
			return TRUE;
		}
	} else {
		if (   state == NM_STATE_CONNECTED_LOCAL
		    || state == NM_STATE_CONNECTED_SITE
		    || state == NM_STATE_CONNECTED_GLOBAL) {
			_return (data, EXIT_SUCCESS);
			return TRUE;
		}
	}
	if (data->exit_no_nm && (state != NM_STATE_CONNECTING)) {
		_return (data, EXIT_FAILURE_OFFLINE);
		return TRUE;
	}

	return FALSE;
}

static void
client_properties_changed (GObject *object,
                           GParamSpec *pspec,
                           gpointer user_data)
{
	quit_if_connected (user_data);
}

static gboolean
handle_timeout (gpointer user_data)
{
	OnlineData *data = user_data;
	const gint64 now = _now_ms ();
	gint64 remaining_ms = data->end_timestamp_ms - now;
	const gint64 elapsed_ms = now - data->start_timestamp_ms;
	int progress_next_step_i = 0;

	data->handle_timeout_id = 0;

	if (remaining_ms <= 3) {
		_return (data, EXIT_FAILURE_OFFLINE);
		return G_SOURCE_REMOVE;
	}

	if (!data->quiet) {
		gint64 rem;

		/* calculate the next step (not the current): floor()+1 */
		progress_next_step_i = NM_MIN ((elapsed_ms / data->progress_step_duration) + 1, PROGRESS_STEPS);
		_print_progress (progress_next_step_i, remaining_ms, -1);

		/* synchronize the timeout with the ticking of the seconds. */
		rem = remaining_ms % 1000;
		if (rem <= 3)
			rem = rem + G_USEC_PER_SEC;
		/* add small offset to awake a bit after the second ticks */
		remaining_ms = NM_MIN (remaining_ms, rem + 10);

		/* synchronize the timeout with the steps of the progress bar. */
		rem = (progress_next_step_i * data->progress_step_duration) - elapsed_ms;
		if (rem <= 3)
			rem = rem + data->progress_step_duration;
		/* add small offset to awake a bit after the second ticks */
		remaining_ms = NM_MIN (remaining_ms, rem + 10);
	}

	data->handle_timeout_id = g_timeout_add (remaining_ms, handle_timeout, data);
	return G_SOURCE_REMOVE;
}

static gboolean
got_client_timeout (gpointer user_data)
{
	OnlineData *data = user_data;

	data->client_new_timeout_id = 0;
	data->quiet = TRUE;
	g_printerr (_("Error: timeout creating NMClient object\n"));
	_return (data, EXIT_FAILURE_LIBNM_BUG);
	return G_SOURCE_REMOVE;
}

static void
got_client (GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	OnlineData *data = user_data;
	gs_free_error GError *error = NULL;
	NMClient *client;

	nm_clear_g_source (&data->client_new_timeout_id);
	g_clear_object (&data->client_new_cancellable);

	client = nm_client_new_finish (res, &error);
	if (!client) {
		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			return;
		data->quiet = TRUE;
		g_printerr (_("Error: Could not create NMClient object: %s\n"),
		            error->message);
		_return (data, EXIT_FAILURE_ERROR);
		return;
	}

	data->client = client;

	if (quit_if_connected (data))
		return;

	data->client_notify_id = g_signal_connect (data->client, "notify",
	                                           G_CALLBACK (client_properties_changed), data);
	data->handle_timeout_id = g_timeout_add (data->quiet ? NM_MAX (0, data->end_timestamp_ms - _now_ms ()) : 0, handle_timeout, data);
}

int
main (int argc, char *argv[])
{
	OnlineData data = {
		.retval = EXIT_FAILURE_UNSPECIFIED,
	};
	int t_secs = 30;
	GOptionContext *opt_ctx = NULL;
	gboolean success;
	GOptionEntry options[] = {
		{"timeout", 't', 0, G_OPTION_ARG_INT, &t_secs, N_("Time to wait for a connection, in seconds (without the option, default value is 30)"), "<timeout>"},
		{"exit", 'x', 0, G_OPTION_ARG_NONE, &data.exit_no_nm, N_("Exit immediately if NetworkManager is not running or connecting"), NULL},
		{"quiet", 'q', 0, G_OPTION_ARG_NONE, &data.quiet, N_("Don't print anything"), NULL},
		{"wait-for-startup", 's', 0, G_OPTION_ARG_NONE, &data.wait_startup, N_("Wait for NetworkManager startup instead of a connection"), NULL},
		{ NULL },
	};

	/* Set locale to be able to use environment variables */
	setlocale (LC_ALL, "");

	bindtextdomain (GETTEXT_PACKAGE, NMLOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	data.start_timestamp_ms = _now_ms ();

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
		return EXIT_FAILURE_ERROR;
	}

	if (t_secs < 0 || t_secs > 3600)  {
		g_printerr ("%s: %s\n", argv[0],
		            _("Invalid option.  Please use --help to see a list of valid options."));
		return EXIT_FAILURE_ERROR;
	}

	if (t_secs == 0)
		data.quiet = TRUE;

	data.loop = g_main_loop_new (NULL, FALSE);

	data.end_timestamp_ms = data.start_timestamp_ms + (t_secs * 1000);
	data.progress_step_duration = NM_MAX (1, (data.end_timestamp_ms - data.start_timestamp_ms + PROGRESS_STEPS/2) / PROGRESS_STEPS);

	data.client_new_cancellable = g_cancellable_new ();

	data.client_new_timeout_id = g_timeout_add_seconds (30, got_client_timeout, &data);
	nm_client_new_async (data.client_new_cancellable, got_client, &data);

	g_main_loop_run (data.loop);

	nm_clear_g_cancellable (&data.client_new_cancellable);
	nm_clear_g_source (&data.client_new_timeout_id);
	nm_clear_g_source (&data.handle_timeout_id);
	nm_clear_g_signal_handler (data.client, &data.client_notify_id);
	g_clear_object (&data.client);

	g_clear_pointer (&data.loop, g_main_loop_unref);

	if (!data.quiet)
		_print_progress (-1, NM_MAX (0, data.end_timestamp_ms - _now_ms ()), data.retval == EXIT_SUCCESS);

	return data.retval;
}
