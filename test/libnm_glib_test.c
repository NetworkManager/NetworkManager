/* libnm_glib_test - test app for libnm_glib
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "libnm_glib.h"


static void status_printer (libnm_glib_ctx *ctx, gpointer user_data)
{
	libnm_glib_state	state;

	g_return_if_fail (ctx != NULL);

	state = libnm_glib_get_network_state (ctx);
	switch (state)
	{
		case LIBNM_NO_DBUS:
			fprintf (stderr, "Status: No DBUS\n");
			break;
		case LIBNM_NO_NETWORKMANAGER:
			fprintf (stderr, "Status: No NetworkManager\n");
			break;
		case LIBNM_NO_NETWORK_CONNECTION:
			fprintf (stderr, "Status: No Connection\n");
			break;
		case LIBNM_ACTIVE_NETWORK_CONNECTION:
			fprintf (stderr, "Status: Active Connection\n");
			break;
		case LIBNM_INVALID_CONTEXT:
			fprintf (stderr, "Status: Error\n");
			break;
		default:
			fprintf (stderr, "Status: unknown\n");
			break;
	}
}

static GMainLoop *loop = NULL;

static void
signal_handler (int signo)
{
	if (signo == SIGINT || signo == SIGTERM) {
		g_message ("Caught signal %d, shutting down...", signo);
		g_main_loop_quit (loop);
	}
}

static void
setup_signals (void)
{
	struct sigaction action;
	sigset_t mask;

	sigemptyset (&mask);
	action.sa_handler = signal_handler;
	action.sa_mask = mask;
	action.sa_flags = 0;
	sigaction (SIGTERM,  &action, NULL);
	sigaction (SIGINT,  &action, NULL);
}

int main( int argc, char *argv[] )
{
	libnm_glib_ctx *ctx;
	guint id;

	ctx = libnm_glib_init ();
	if (!ctx)
	{
		fprintf (stderr, "Could not initialize libnm.\n");
		exit (1);
	}

	id = libnm_glib_register_callback (ctx, status_printer, ctx, NULL);
	fprintf (stderr, "Registered Callback with ID %d\n", id);
	libnm_glib_unregister_callback (ctx, id);
	fprintf (stderr, "Unregistered Callback with ID %d\n", id);

	id = libnm_glib_register_callback (ctx, status_printer, ctx, NULL);
	fprintf (stderr, "Registered Callback with ID %d\n", id);

	loop = g_main_loop_new (NULL, FALSE);
	setup_signals ();
	g_main_loop_run (loop);

	libnm_glib_shutdown (ctx);

	exit (0);
}
