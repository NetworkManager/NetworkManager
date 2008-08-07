/* NetworkManager -- Network link manager
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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <getopt.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <glib/gi18n.h>
#include <string.h>

#include "NetworkManager.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-manager.h"
#include "NetworkManagerPolicy.h"
#include "NetworkManagerSystem.h"
#include "nm-named-manager.h"
#include "nm-dbus-manager.h"
#include "nm-supplicant-manager.h"
#include "nm-netlink-monitor.h"
#include "nm-vpn-manager.h"
#include "nm-logging.h"

#define NM_DEFAULT_PID_FILE	LOCALSTATEDIR"/run/NetworkManager.pid"

/*
 * Globals
 */
static NMManager *manager = NULL;
static GMainLoop *main_loop = NULL;

static void
nm_error_monitoring_device_link_state (NMNetlinkMonitor *monitor,
									   GError *error,
									   gpointer user_data)
{
	/* FIXME: Try to handle the error instead of just printing it. */
	nm_warning ("error monitoring wired ethernet link state: %s\n",
				error->message);
}

static gboolean
nm_monitor_setup (void)
{
	GError *error = NULL;
	NMNetlinkMonitor *monitor;

	monitor = nm_netlink_monitor_get ();
	nm_netlink_monitor_open_connection (monitor, &error);
	if (error != NULL)
	{
		nm_warning ("could not monitor wired ethernet devices: %s",
					error->message);
		g_error_free (error);
		g_object_unref (monitor);
		return FALSE;
	}

	g_signal_connect (G_OBJECT (monitor), "error",
			  G_CALLBACK (nm_error_monitoring_device_link_state),
			  NULL);

	nm_netlink_monitor_attach (monitor, NULL);

	/* Request initial status of cards */
	nm_netlink_monitor_request_status (monitor, NULL);

	return TRUE;
}

static gboolean quit_early = FALSE;

static void
nm_signal_handler (int signo)
{
	static int in_fatal = 0;

	/* avoid loops */
	if (in_fatal > 0)
		return;
	++in_fatal;

	switch (signo)
	{
		case SIGSEGV:
		case SIGBUS:
		case SIGILL:
		case SIGABRT:
			nm_warning ("Caught signal %d.  Generating backtrace...", signo);
			nm_logging_backtrace ();
			exit (1);
			break;

		case SIGFPE:
		case SIGPIPE:
			/* let the fatal signals interrupt us */
			--in_fatal;

			nm_warning ("Caught signal %d, shutting down abnormally.  Generating backtrace...", signo);
			nm_logging_backtrace ();
			g_main_loop_quit (main_loop);
			break;

		case SIGINT:
		case SIGTERM:
			/* let the fatal signals interrupt us */
			--in_fatal;

			nm_warning ("Caught signal %d, shutting down normally.", signo);
			quit_early = TRUE;
			g_main_loop_quit (main_loop);
			break;

		case SIGHUP:
			--in_fatal;
			/* FIXME:
			 * Reread config stuff like system config files, VPN service files, etc
			 */
			break;

		case SIGUSR1:
			--in_fatal;
			/* FIXME:
			 * Play with log levels or something
			 */
			break;

		default:
			signal (signo, nm_signal_handler);
			break;
	}
}

static void
setup_signals (void)
{
	struct sigaction action;
	sigset_t mask;

	sigemptyset (&mask);
	action.sa_handler = nm_signal_handler;
	action.sa_mask = mask;
	action.sa_flags = 0;
	sigaction (SIGTERM,  &action, NULL);
	sigaction (SIGINT,  &action, NULL);
	sigaction (SIGILL,  &action, NULL);
	sigaction (SIGBUS,  &action, NULL);
	sigaction (SIGFPE,  &action, NULL);
	sigaction (SIGHUP,  &action, NULL);
	sigaction (SIGSEGV, &action, NULL);
	sigaction (SIGABRT, &action, NULL);
	sigaction (SIGUSR1,  &action, NULL);
}

static void
write_pidfile (const char *pidfile)
{
 	char pid[16];
	int fd;
 
	if ((fd = open (pidfile, O_CREAT|O_WRONLY|O_TRUNC, 00644)) < 0)
	{
		nm_warning ("Opening %s failed: %s", pidfile, strerror (errno));
		return;
	}
 	snprintf (pid, sizeof (pid), "%d", getpid ());
	if (write (fd, pid, strlen (pid)) < 0)
		nm_warning ("Writing to %s failed: %s", pidfile, strerror (errno));
	if (close (fd))
		nm_warning ("Closing %s failed: %s", pidfile, strerror (errno));
}

/*
 * main
 *
 */
int
main (int argc, char *argv[])
{
	GOptionContext *opt_ctx = NULL;
	gboolean		become_daemon = FALSE;
	char *		pidfile = NULL;
	char *		user_pidfile = NULL;
	gboolean success;
	NMPolicy *policy = NULL;
	NMVPNManager *vpn_manager = NULL;
	NMNamedManager *named_mgr = NULL;
	NMDBusManager *	dbus_mgr = NULL;
	NMSupplicantManager * sup_mgr = NULL;

	GOptionEntry options[] = {
		{"no-daemon", 0, 0, G_OPTION_ARG_NONE, &become_daemon, "Don't become a daemon", NULL},
		{"pid-file", 0, 0, G_OPTION_ARG_FILENAME, &user_pidfile, "Specify the location of a PID file", "filename"},
		{NULL}
	};

	if (getuid () != 0) {
		g_printerr ("You must be root to run NetworkManager!\n");
		exit (1);
	}

	bindtextdomain (GETTEXT_PACKAGE, NMLOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	/* Parse options */
	opt_ctx = g_option_context_new ("");
	g_option_context_set_translation_domain (opt_ctx, "UTF-8");
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);

	g_option_context_set_summary (opt_ctx,
		"NetworkManager monitors all network connections and automatically\nchooses the best connection to use.  It also allows the user to\nspecify wireless access points which wireless cards in the computer\nshould associate with.");

	success = g_option_context_parse (opt_ctx, &argc, &argv, NULL);
	g_option_context_free (opt_ctx);

	if (!success) {
		fprintf (stderr, _("Invalid option.  Please use --help to see a list of valid options.\n"));
		exit (1);
	}

	pidfile = g_strdup (user_pidfile ? user_pidfile : NM_DEFAULT_PID_FILE);

	/* Tricky: become_daemon is FALSE by default, so unless it's TRUE because
	 * of a CLI option, it'll become TRUE after this
	 */
	become_daemon = !become_daemon;
	if (become_daemon) {
		if (daemon (0, 0) < 0) {
			int saved_errno;

			saved_errno = errno;
			nm_error ("Could not daemonize: %s [error %u]",
			          g_strerror (saved_errno),
			          saved_errno);
			exit (1);
		}
		write_pidfile (pidfile);
	}

	/*
	 * Set the umask to 0022, which results in 0666 & ~0022 = 0644.
	 * Otherwise, if root (or an su'ing user) has a wacky umask, we could
	 * write out an unreadable resolv.conf.
	 */
	umask (022);

	g_type_init ();
	if (!g_thread_supported ())
		g_thread_init (NULL);
	dbus_g_thread_init ();

	setup_signals ();

	nm_logging_setup (become_daemon);
	nm_info ("starting...");

	main_loop = g_main_loop_new (NULL, FALSE);

	/* Create watch functions that monitor cards for link status. */
	if (!nm_monitor_setup ())
		goto done;

	/* Initialize our DBus service & connection */
	dbus_mgr = nm_dbus_manager_get ();

	vpn_manager = nm_vpn_manager_get ();
	if (!vpn_manager) {
		nm_warning ("Failed to start the VPN manager.");
		goto done;
	}

	manager = nm_manager_get ();
	if (manager == NULL) {
		nm_error ("Failed to initialize the network manager.");
		goto done;
	}

	policy = nm_policy_new (manager);
	if (policy == NULL) {
		nm_error ("Failed to initialize the policy.");
		goto done;
	}

	/* Initialize the supplicant manager */
	sup_mgr = nm_supplicant_manager_get ();
	if (!sup_mgr) {
		nm_error ("Failed to initialize the supplicant manager.");
		goto done;
	}

	named_mgr = nm_named_manager_get ();
	if (!named_mgr) {
		nm_warning ("Failed to start the named manager.");
		goto done;
	}

	/* Start our DBus service */
	if (!nm_dbus_manager_start_service (dbus_mgr)) {
		nm_warning ("Failed to start the dbus manager.");
		goto done;
	}

	/* Bring up the loopback interface. */
	nm_system_enable_loopback ();

	/* Told to quit before getting to the mainloop by the signal handler */
	if (quit_early == TRUE)
		goto done;

	g_main_loop_run (main_loop);

done:
	if (policy)
		nm_policy_destroy (policy);

	if (manager)
		g_object_unref (manager);

	if (vpn_manager)
		g_object_unref (vpn_manager);

	if (sup_mgr)
		g_object_unref (sup_mgr);

	if (dbus_mgr)
		g_object_unref (dbus_mgr);

	nm_logging_shutdown ();

	if (pidfile)
		unlink (pidfile);
	g_free (pidfile);

	exit (0);
}
