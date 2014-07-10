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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <locale.h>

#include <glib/gi18n.h>

#include <NetworkManager.h>
#include "nm-glib-compat.h"

#define PROGRESS_STEPS 15
#define WAIT_STARTUP_TAG "wait-startup"

typedef struct
{
	gint64 start_timestamp_ms;
	gint64 end_timestamp_ms;
	gint64 progress_step_duration;
	gboolean quiet;
} Timeout;

static void
client_properties_changed (GObject *object,
                           GParamSpec *pspec,
                           gpointer loop)
{
	NMClient *client = NM_CLIENT (object);
	NMState state;
	gboolean wait_startup = GPOINTER_TO_UINT (g_object_get_data (object, WAIT_STARTUP_TAG));

	if (!nm_client_get_nm_running (client))
		return;

	if (wait_startup) {
		if (!nm_client_get_startup (client))
			g_main_loop_quit (loop);
	} else {
		state = nm_client_get_state (client);
		if (   state == NM_STATE_CONNECTED_LOCAL
		    || state == NM_STATE_CONNECTED_SITE
		    || state == NM_STATE_CONNECTED_GLOBAL)
			g_main_loop_quit (loop);
	}
}

static gboolean
handle_timeout (gpointer data)
{
	const Timeout *timeout = data;
	const gint64 now = g_get_monotonic_time () / (G_USEC_PER_SEC / 1000);
	gint64 remaining_ms = timeout->end_timestamp_ms - now;
	const gint64 elapsed_ms = now - timeout->start_timestamp_ms;
	int progress_next_step_i = 0;

	if (!timeout->quiet) {
		int i;

		/* calculate the next step (not the current): floor()+1 */
		progress_next_step_i = (elapsed_ms / timeout->progress_step_duration) + 1;
		progress_next_step_i = MIN (progress_next_step_i, PROGRESS_STEPS);

		g_print (_("\rConnecting"));
		for (i = 0; i < PROGRESS_STEPS; i++)
			putchar (i < progress_next_step_i ? '.' : ' ');
		g_print (" %4lds", (long) (MAX (0, remaining_ms) / 1000));
		fflush (stdout);
	}

	if (remaining_ms <= 3) {
		if (!timeout->quiet)
			g_print ("\n");
		exit (1);
	}

	if (!timeout->quiet) {
		gint64 rem;

		/* synchronize the timeout with the ticking of the seconds. */
		rem = remaining_ms % 1000;
		if (rem <= 3)
			rem = rem + G_USEC_PER_SEC;
		rem = rem + 10; /* add small offset to awake a bit after the second ticks */
		if (remaining_ms > rem)
			remaining_ms = rem;

		/* synchronize the timeout with the steps of the progress bar. */
		rem = (progress_next_step_i * timeout->progress_step_duration) - elapsed_ms;
		if (rem <= 3)
			rem = rem + timeout->progress_step_duration;
		rem = rem + 10; /* add small offset to awake a bit after the time out */
		if (remaining_ms > rem)
			remaining_ms = rem;
	}

	g_timeout_add (remaining_ms, handle_timeout, (void *) timeout);
	return G_SOURCE_REMOVE;
}

int
main (int argc, char *argv[])
{
	int t_secs = 30;
	gboolean exit_no_nm = FALSE;
	gboolean wait_startup = FALSE;
	Timeout timeout;
	GOptionContext *opt_ctx = NULL;
	gboolean success;
	NMClient *client;
	NMState state = NM_STATE_UNKNOWN;
	GMainLoop *loop;
	gint64 remaining_ms;
	GError *error = NULL;

	GOptionEntry options[] = {
		{"timeout", 't', 0, G_OPTION_ARG_INT, &t_secs, N_("Time to wait for a connection, in seconds (without the option, default value is 30)"), "<timeout>"},
		{"exit", 'x', 0, G_OPTION_ARG_NONE, &exit_no_nm, N_("Exit immediately if NetworkManager is not running or connecting"), NULL},
		{"quiet", 'q', 0, G_OPTION_ARG_NONE, &timeout.quiet, N_("Don't print anything"), NULL},
		{"wait-for-startup", 's', 0, G_OPTION_ARG_NONE, &wait_startup, N_("Wait for NetworkManager startup instead of a connection"), NULL},
		{NULL}
	};

	timeout.start_timestamp_ms = g_get_monotonic_time () / (G_USEC_PER_SEC / 1000);
	timeout.quiet = FALSE;

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
	remaining_ms = t_secs * 1000;

	nm_g_type_init ();

	client = nm_client_new (NULL, &error);
	if (!client) {
		g_printerr (_("Error: Could not create NMClient object: %s."), error->message);
		g_error_free (error);
		return 2;
	}

	loop = g_main_loop_new (NULL, FALSE);

	g_object_set_data (G_OBJECT (client), WAIT_STARTUP_TAG, GUINT_TO_POINTER (wait_startup));
	state = nm_client_get_state (client);
	if (!nm_client_get_nm_running (client)) {
		if (exit_no_nm) {
			g_object_unref (client);
			return 1;
		}
	} else if (wait_startup) {
		if (!nm_client_get_startup (client)) {
			g_object_unref (client);
			return 0;
		}
	} else {
		if (   state == NM_STATE_CONNECTED_LOCAL
		    || state == NM_STATE_CONNECTED_SITE
		    || state == NM_STATE_CONNECTED_GLOBAL) {
			g_object_unref (client);
			return 0;
		}
	}
	if (exit_no_nm && (state != NM_STATE_CONNECTING)) {
		g_object_unref (client);
		return 1;
	}

	if (remaining_ms == 0) {
		g_object_unref (client);
		return 1;
	}

	g_signal_connect (client, "notify",
	                  G_CALLBACK (client_properties_changed), loop);

	timeout.end_timestamp_ms = timeout.start_timestamp_ms + remaining_ms;
	timeout.progress_step_duration = (timeout.end_timestamp_ms - timeout.start_timestamp_ms + PROGRESS_STEPS/2) / PROGRESS_STEPS;

	g_timeout_add (timeout.quiet ? remaining_ms : 0,
	               handle_timeout, &timeout);

	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	g_object_unref (client);

	return 0;
}
