/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2004 - 2012 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <locale.h>

#include <glib.h>
#include <glib/gi18n.h>
#include <glib-unix.h>
#include <gmodule.h>

#include "main-utils.h"
#include "nm-logging.h"

static gboolean
sighup_handler (gpointer user_data)
{
	/* Reread config stuff like system config files, VPN service files, etc */
	nm_log_info (LOGD_CORE, "caught SIGHUP, not supported yet.");

	return G_SOURCE_CONTINUE;
}

static gboolean
sigint_handler (gpointer user_data)
{
	GMainLoop *main_loop = user_data;

	nm_log_info (LOGD_CORE, "caught SIGINT, shutting down normally.");
	g_main_loop_quit (main_loop);

	return G_SOURCE_REMOVE;
}

static gboolean
sigterm_handler (gpointer user_data)
{
	GMainLoop *main_loop = user_data;

	nm_log_info (LOGD_CORE, "caught SIGTERM, shutting down normally.");
	g_main_loop_quit (main_loop);

	return G_SOURCE_REMOVE;
}

/**
 * nm_main_utils_setup_signals:
 * @main_loop: the #GMainLoop to quit when SIGINT or SIGTERM is received
 *
 * Sets up signal handling for NetworkManager.
 */
void
nm_main_utils_setup_signals (GMainLoop *main_loop)
{
	g_return_if_fail (main_loop != NULL);

	signal (SIGPIPE, SIG_IGN);

	g_unix_signal_add (SIGHUP, sighup_handler, NULL);
	g_unix_signal_add (SIGINT, sigint_handler, main_loop);
	g_unix_signal_add (SIGTERM, sigterm_handler, main_loop);
}

gboolean
nm_main_utils_write_pidfile (const char *pidfile)
{
	char pid[16];
	int fd;
	gboolean success = FALSE;

	if ((fd = open (pidfile, O_CREAT|O_WRONLY|O_TRUNC, 00644)) < 0) {
		fprintf (stderr, _("Opening %s failed: %s\n"), pidfile, strerror (errno));
		return FALSE;
	}

	g_snprintf (pid, sizeof (pid), "%d", getpid ());
	if (write (fd, pid, strlen (pid)) < 0)
		fprintf (stderr, _("Writing to %s failed: %s\n"), pidfile, strerror (errno));
	else
		success = TRUE;

	if (close (fd))
		fprintf (stderr, _("Closing %s failed: %s\n"), pidfile, strerror (errno));

	return success;
}

/**
 * nm_main_utils_check_pidfile:
 * @pidfile: the pid file
 * @name: the process name
 *
 * Checks whether the pidfile already exists and contains PID of a running
 * process.
 *
 * Returns: %TRUE if the specified pidfile already exists and contains the PID
 *  of a running process named @name, or %FALSE if not
 */
gboolean
nm_main_utils_check_pidfile (const char *pidfile, const char *name)
{
	char *contents = NULL;
	gsize len = 0;
	glong pid;
	char *proc_cmdline = NULL;
	gboolean nm_running = FALSE;
	const char *process_name;

	/* Setup runtime directory */
	if (g_mkdir_with_parents (NMRUNDIR, 0755) != 0) {
		nm_log_err (LOGD_CORE, "Cannot create '%s': %s", NMRUNDIR, strerror (errno));
		exit (1);
	}

	if (!g_file_get_contents (pidfile, &contents, &len, NULL))
		return FALSE;

	if (len <= 0)
		goto done;

	errno = 0;
	pid = strtol (contents, NULL, 10);
	if (pid <= 0 || pid > 65536 || errno)
		goto done;

	g_free (contents);
	proc_cmdline = g_strdup_printf ("/proc/%ld/cmdline", pid);
	if (!g_file_get_contents (proc_cmdline, &contents, &len, NULL))
		goto done;

	process_name = strrchr (contents, '/');
	if (process_name)
		process_name++;
	else
		process_name = contents;
	if (strcmp (process_name, name) == 0) {
		/* Check that the process exists */
		if (kill (pid, 0) == 0) {
			fprintf (stderr, _("%s is already running (pid %ld)\n"), name, pid);
			nm_running = TRUE;
		}
	}

done:
	g_free (proc_cmdline);
	g_free (contents);
	return nm_running;
}

gboolean
nm_main_utils_early_setup (const char *progname,
                           char **argv[],
                           int *argc,
                           GOptionEntry *options,
                           GOptionEntry *more_options,
                           const char *summary)
{
	GOptionContext *opt_ctx = NULL;
	GError *error = NULL;
	gboolean success = FALSE;
	int i;

	/* Make GIO ignore the remote VFS service; otherwise it tries to use the
	 * session bus to contact the remote service, and NM shouldn't ever be
	 * talking on the session bus.  See rh #588745
	 */
	setenv ("GIO_USE_VFS", "local", 1);

	/*
	 * Set the umask to 0022, which results in 0666 & ~0022 = 0644.
	 * Otherwise, if root (or an su'ing user) has a wacky umask, we could
	 * write out an unreadable resolv.conf.
	 */
	umask (022);

	/* Ensure gettext() gets the right environment (bgo #666516) */
	setlocale (LC_ALL, "");
	textdomain (GETTEXT_PACKAGE);

	if (getuid () != 0) {
		fprintf (stderr, _("You must be root to run %s!\n"), progname);
		exit (1);
	}

	for (i = 0; options[i].long_name; i++) {
		if (!strcmp (options[i].long_name, "log-level"))
			options[i].description = g_strdup_printf (options[i].description, nm_logging_all_levels_to_string ());
		else if (!strcmp (options[i].long_name, "log-domains"))
			options[i].description = g_strdup_printf (options[i].description, nm_logging_all_domains_to_string ());
	}

	/* Parse options */
	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_translation_domain (opt_ctx, GETTEXT_PACKAGE);
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);
	if (more_options)
		g_option_context_add_main_entries (opt_ctx, more_options, NULL);
	g_option_context_set_summary (opt_ctx, summary);

	success = g_option_context_parse (opt_ctx, argc, argv, &error);
	if (!success) {
		fprintf (stderr, _("%s.  Please use --help to see a list of valid options.\n"),
		         error->message);
		g_clear_error (&error);
	}
	g_option_context_free (opt_ctx);

	return success;
}

