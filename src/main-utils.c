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

#include <glib-unix.h>
#include <gmodule.h>

#include "nm-default.h"
#include "main-utils.h"
#include "NetworkManagerUtils.h"

static gboolean
sighup_handler (gpointer user_data)
{
	nm_main_config_reload (GPOINTER_TO_INT (user_data));
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

	g_unix_signal_add (SIGHUP, sighup_handler, GINT_TO_POINTER (SIGHUP));
	g_unix_signal_add (SIGUSR1, sighup_handler, GINT_TO_POINTER (SIGUSR1));
	g_unix_signal_add (SIGUSR2, sighup_handler, GINT_TO_POINTER (SIGUSR2));
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

void
nm_main_utils_ensure_rundir ()
{
	/* Setup runtime directory */
	if (g_mkdir_with_parents (NMRUNDIR, 0755) != 0) {
		fprintf (stderr, _("Cannot create '%s': %s"), NMRUNDIR, strerror (errno));
		exit (1);
	}
}

/**
 * nm_main_utils_ensure_not_running_pidfile:
 * @pidfile: the pid file
 *
 * Checks whether the pidfile already exists and contains PID of a running
 * process.
 *
 * Exits with code 1 if a conflicting process is running.
 */
void
nm_main_utils_ensure_not_running_pidfile (const char *pidfile)
{
	gs_free char *contents = NULL;
	gs_free char *proc_cmdline = NULL;
	gsize len = 0;
	glong pid;
	const char *process_name;
	const char *prgname = g_get_prgname ();

	g_return_if_fail (prgname);

	if (!pidfile || !*pidfile)
		return;

	if (!g_file_get_contents (pidfile, &contents, &len, NULL))
		return;
	if (len <= 0)
		return;

	errno = 0;
	pid = strtol (contents, NULL, 10);
	if (pid <= 0 || pid > 65536 || errno)
		return;

	g_clear_pointer (&contents, g_free);
	proc_cmdline = g_strdup_printf ("/proc/%ld/cmdline", pid);
	if (!g_file_get_contents (proc_cmdline, &contents, &len, NULL))
		return;

	process_name = strrchr (contents, '/');
	if (process_name)
		process_name++;
	else
		process_name = contents;
	if (strcmp (process_name, prgname) == 0) {
		/* Check that the process exists */
		if (kill (pid, 0) == 0) {
			fprintf (stderr, _("%s is already running (pid %ld)\n"), prgname, pid);
			exit (1);
		}
	}
}

void
nm_main_utils_ensure_root ()
{
	if (getuid () != 0) {
		fprintf (stderr, _("You must be root to run %s!\n"), str_if_set (g_get_prgname (), ""));
		exit (1);
	}
}

gboolean
nm_main_utils_early_setup (const char *progname,
                           int *argc,
                           char **argv[],
                           GOptionEntry *options,
                           void (*option_context_hook) (gpointer user_data, GOptionContext *opt_ctx),
                           gpointer option_context_hook_data,
                           const char *summary)
{
	GOptionContext *opt_ctx = NULL;
	GError *error = NULL;
	gboolean success = FALSE;
	int i;
	const char *opt_fmt_log_level = NULL, *opt_fmt_log_domains = NULL;
	const char **opt_loc_log_level = NULL, **opt_loc_log_domains = NULL;

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

	for (i = 0; options[i].long_name; i++) {
		if (!strcmp (options[i].long_name, "log-level")) {
			opt_fmt_log_level = options[i].description;
			opt_loc_log_level = &options[i].description;
			options[i].description = g_strdup_printf (options[i].description, nm_logging_all_levels_to_string ());
		} else if (!strcmp (options[i].long_name, "log-domains")) {
			opt_fmt_log_domains = options[i].description;
			opt_loc_log_domains = &options[i].description;
			options[i].description = g_strdup_printf (options[i].description, nm_logging_all_domains_to_string ());
		}
	}

	/* Parse options */
	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_translation_domain (opt_ctx, GETTEXT_PACKAGE);
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);
	g_option_context_set_summary (opt_ctx, summary);
	if (option_context_hook)
		option_context_hook (option_context_hook_data, opt_ctx);

	success = g_option_context_parse (opt_ctx, argc, argv, &error);
	if (!success) {
		fprintf (stderr, _("%s.  Please use --help to see a list of valid options.\n"),
		         error->message);
		g_clear_error (&error);
	}
	g_option_context_free (opt_ctx);

	if (opt_loc_log_level) {
		g_free ((char *) *opt_loc_log_level);
		*opt_loc_log_level = opt_fmt_log_level;
	}
	if (opt_loc_log_domains) {
		g_free ((char *) *opt_loc_log_domains);
		*opt_loc_log_domains = opt_fmt_log_domains;
	}

	return success;
}

