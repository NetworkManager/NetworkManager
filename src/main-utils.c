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
#include <gmodule.h>

#include "gsystem-local-alloc.h"
#include "main-utils.h"
#include "nm-posix-signals.h"
#include "NetworkManagerUtils.h"
#include "nm-logging.h"

static sigset_t signal_set;
static gboolean *quit_early = NULL;

/*
 * Thread function waiting for signals and processing them.
 * Wait for signals in signal set. The semantics of sigwait() require that all
 * threads (including the thread calling sigwait()) have the signal masked, for
 * reliable operation. Otherwise, a signal that arrives while this thread is
 * not blocked in sigwait() might be delivered to another thread.
 */
static void *
signal_handling_thread (void *arg)
{
	GMainLoop *main_loop = arg;
	int signo;

	while (1) {
		sigwait (&signal_set, &signo);

		switch (signo) {
		case SIGINT:
		case SIGTERM:
			nm_log_info (LOGD_CORE, "caught signal %d, shutting down normally.", signo);
			*quit_early = TRUE; /* for quitting before entering the main loop */
			g_main_loop_quit (main_loop);
			break;
		case SIGHUP:
			/* Reread config stuff like system config files, VPN service files, etc */
			nm_log_info (LOGD_CORE, "caught signal %d, not supported yet.", signo);
			break;
		case SIGPIPE:
			/* silently ignore signal */
			break;
		default:
			nm_log_err (LOGD_CORE, "caught unexpected signal %d", signo);
			break;
		}
    }
    return NULL;
}

/**
 * nm_main_utils_setup_signals:
 * @main_loop: the #GMainLoop to quit when SIGINT or SIGTERM is received
 * @quit_early: location of a variable that will be set to TRUE when
 *   SIGINT or SIGTERM is received
 *
 * Mask the signals we are interested in and create a signal handling thread.
 * Because all threads inherit the signal mask from their creator, all threads
 * in the process will have the signals masked. That's why setup_signals() has
 * to be called before creating other threads.
 *
 * Returns: %TRUE on success
 */
gboolean
nm_main_utils_setup_signals (GMainLoop *main_loop, gboolean *quit_early_ptr)
{
	pthread_t signal_thread_id;
	sigset_t old_sig_mask;
	int status;

	g_return_val_if_fail (main_loop != NULL, FALSE);
	g_return_val_if_fail (quit_early_ptr != NULL, FALSE);

	quit_early = quit_early_ptr;

	sigemptyset (&signal_set);
	sigaddset (&signal_set, SIGHUP);
	sigaddset (&signal_set, SIGINT);
	sigaddset (&signal_set, SIGTERM);
	sigaddset (&signal_set, SIGPIPE);

	/* Block all signals of interest. */
	status = pthread_sigmask (SIG_BLOCK, &signal_set, &old_sig_mask);
	if (status != 0) {
		fprintf (stderr, _("Failed to set signal mask: %d"), status);
		return FALSE;
	}
	/* Save original mask so that we could use it for child processes. */
	nm_save_original_signal_mask (old_sig_mask);

	/* Create the signal handling thread. */
	status = pthread_create (&signal_thread_id, NULL, signal_handling_thread, main_loop);
	if (status != 0) {
		fprintf (stderr, _("Failed to create signal handling thread: %d"), status);
		return FALSE;
	}

	return TRUE;
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

