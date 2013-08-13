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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <locale.h>

#include <glib/gi18n.h>

#include "nm-client.h"

#define PROGRESS_STEPS 15

typedef struct
{
	int value;
	double norm;
	gboolean quiet;
} Timeout;

static void
client_properties_changed (GObject *object,
                           GParamSpec *pspec,
                           gpointer loop)
{
	NMClient *client = NM_CLIENT (object);

	if (!nm_client_get_manager_running (client))
		return;
	if (!nm_client_get_startup (client))
		g_main_loop_quit (loop);
}

static gboolean
handle_timeout (gpointer data)
{
	int i = PROGRESS_STEPS;
	Timeout *timeout = data;

	if (!timeout->quiet) {
		g_print (_("\rConnecting"));
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

int
main (int argc, char *argv[])
{
	gint t_secs = -1;
	gboolean exit_no_nm = FALSE;
	gboolean quiet = FALSE;
	Timeout timeout;
	GOptionContext *opt_ctx = NULL;
	gboolean success;
	NMClient *client;
	GMainLoop *loop;

	GOptionEntry options[] = {
		{"timeout", 't', 0, G_OPTION_ARG_INT, &t_secs, N_("Time to wait for a connection, in seconds (without the option, default value is 30)"), "<timeout>"},
		{"exit", 'x', 0, G_OPTION_ARG_NONE, &exit_no_nm, N_("Exit immediately if NetworkManager is not running"), NULL},
		{"quiet", 'q', 0, G_OPTION_ARG_NONE, &quiet, N_("Don't print anything"), NULL},
		{NULL}
	};

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
	
	if (t_secs > -1)
		timeout.value = t_secs;
	else
		timeout.value = 30;
	if (timeout.value < 0 || timeout.value > 3600)  {
		g_printerr ("%s: %s\n", argv[0],
		            _("Invalid option.  Please use --help to see a list of valid options."));
		return 2;
	}

	g_type_init ();
	loop = g_main_loop_new (NULL, FALSE);

	client = nm_client_new ();

	if (!nm_client_get_manager_running (client)) {
		if (exit_no_nm)
			return 1;
	} else if (!nm_client_get_startup (client))
		return 0;
	if (!timeout.value)
		return 1;

	timeout.norm = (double) timeout.value / (double) PROGRESS_STEPS;
	g_timeout_add_seconds (1, handle_timeout, &timeout);

	g_signal_connect (client, "notify",
	                  G_CALLBACK (client_properties_changed), loop);

	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	g_object_unref (client);

	return 0;
}
