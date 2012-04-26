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

#include <config.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <getopt.h>
#include <locale.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <glib/gi18n.h>
#include <gmodule.h>
#include <string.h>

#include "NetworkManager.h"
#include "NetworkManagerUtils.h"
#include "nm-manager.h"
#include "nm-policy.h"
#include "backends/nm-backend.h"
#include "nm-dns-manager.h"
#include "nm-dbus-manager.h"
#include "nm-supplicant-manager.h"
#include "nm-dhcp-manager.h"
#include "nm-firewall-manager.h"
#include "nm-hostname-provider.h"
#include "nm-netlink-monitor.h"
#include "nm-vpn-manager.h"
#include "nm-logging.h"
#include "nm-policy-hosts.h"
#include "nm-config.h"

#if !defined(NM_DIST_VERSION)
# define NM_DIST_VERSION VERSION
#endif

#define NM_DEFAULT_PID_FILE          LOCALSTATEDIR"/run/NetworkManager.pid"
#define NM_DEFAULT_SYSTEM_STATE_FILE LOCALSTATEDIR"/lib/NetworkManager/NetworkManager.state"

/*
 * Globals
 */
static NMManager *manager = NULL;
static GMainLoop *main_loop = NULL;
static gboolean quit_early = FALSE;
static sigset_t signal_set;

void *signal_handling_thread (void *arg);
/*
 * Thread function waiting for signals and processing them.
 * Wait for signals in signal set. The semantics of sigwait() require that all
 * threads (including the thread calling sigwait()) have the signal masked, for
 * reliable operation. Otherwise, a signal that arrives while this thread is
 * not blocked in sigwait() might be delivered to another thread.
 */
void *
signal_handling_thread (void *arg)
{
	int signo;

	while (1) {
		sigwait (&signal_set, &signo);

		switch (signo) {
		case SIGSEGV:
		case SIGBUS:
		case SIGILL:
		case SIGABRT:
		case SIGQUIT:
			nm_log_warn (LOGD_CORE, "caught signal %d. Generating backtrace...", signo);
			nm_logging_backtrace ();
			exit (1);
			break;
		case SIGFPE:
		case SIGPIPE:
			nm_log_warn (LOGD_CORE, "caught signal %d, shutting down abnormally. Generating backtrace...", signo);
			nm_logging_backtrace ();
			quit_early = TRUE; /* for quitting before entering the main loop */
			g_main_loop_quit (main_loop);
			break;
		case SIGINT:
		case SIGTERM:
			nm_log_info (LOGD_CORE, "caught signal %d, shutting down normally.", signo);
			quit_early = TRUE; /* for quitting before entering the main loop */
			g_main_loop_quit (main_loop);
			break;
		case SIGHUP:
			/* Reread config stuff like system config files, VPN service files, etc */
			nm_log_info (LOGD_CORE, "caught signal %d, not supported yet.", signo);
			break;
		case SIGUSR1:
			/* Play with log levels or something */
			nm_log_info (LOGD_CORE, "caught signal %d, not supported yet.", signo);
			break;
		default:
			nm_log_err (LOGD_CORE, "caught unexpected signal %d", signo);
			break;
		}
    }
    return NULL;
}

/*
 * Mask the signals we are interested in and create a signal handling thread.
 * Because all threads inherit the signal mask from their creator, all threads
 * in the process will have the signals masked. That's why setup_signals() has
 * to be called before creating other threads.
 */
static gboolean
setup_signals (void)
{
	pthread_t signal_thread_id;
	int status;

	sigemptyset (&signal_set);
	sigaddset (&signal_set, SIGHUP);
	sigaddset (&signal_set, SIGINT);
	sigaddset (&signal_set, SIGQUIT);
	sigaddset (&signal_set, SIGILL);
	sigaddset (&signal_set, SIGABRT);
	sigaddset (&signal_set, SIGFPE);
	sigaddset (&signal_set, SIGBUS);
	sigaddset (&signal_set, SIGSEGV);
	sigaddset (&signal_set, SIGPIPE);
	sigaddset (&signal_set, SIGTERM);
	sigaddset (&signal_set, SIGUSR1);

	/* Block all signals of interest. */
	status = pthread_sigmask (SIG_BLOCK, &signal_set, NULL);
	if (status != 0) {
		fprintf (stderr, _("Failed to set signal mask: %d"), status);
		return FALSE;
	}

	/* Create the signal handling thread. */
	status = pthread_create (&signal_thread_id, NULL, signal_handling_thread, NULL);
	if (status != 0) {
		fprintf (stderr, _("Failed to create signal handling thread: %d"), status);
		return FALSE;
	}

	return TRUE;
}

static gboolean
write_pidfile (const char *pidfile)
{
 	char pid[16];
	int fd;
	gboolean success = FALSE;
 
	if ((fd = open (pidfile, O_CREAT|O_WRONLY|O_TRUNC, 00644)) < 0) {
		fprintf (stderr, _("Opening %s failed: %s\n"), pidfile, strerror (errno));
		return FALSE;
	}

 	snprintf (pid, sizeof (pid), "%d", getpid ());
	if (write (fd, pid, strlen (pid)) < 0)
		fprintf (stderr, _("Writing to %s failed: %s\n"), pidfile, strerror (errno));
	else
		success = TRUE;

	if (close (fd))
		fprintf (stderr, _("Closing %s failed: %s\n"), pidfile, strerror (errno));

	return success;
}

/* Check whether the pidfile already exists and contains PID of a running NetworkManager
 *  Returns:  FALSE - specified pidfile doesn't exist or doesn't contain PID of a running NM process
 *            TRUE  - specified pidfile already exists and contains PID of a running NM process
 */
static gboolean
check_pidfile (const char *pidfile)
{
	char *contents = NULL;
	gsize len = 0;
	glong pid;
	char *proc_cmdline = NULL;
	gboolean nm_running = FALSE;
	const char *process_name;

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
	if (strcmp (process_name, "NetworkManager") == 0) {
		/* Check that the process exists */
		if (kill (pid, 0) == 0) {
			fprintf (stderr, _("NetworkManager is already running (pid %ld)\n"), pid);
			nm_running = TRUE;
		}
	}

done:
	g_free (proc_cmdline);
	g_free (contents);
	return nm_running;
}

static gboolean
parse_state_file (const char *filename,
                  gboolean *net_enabled,
                  gboolean *wifi_enabled,
                  gboolean *wwan_enabled,
                  gboolean *wimax_enabled,
                  GError **error)
{
	GKeyFile *state_file;
	GError *tmp_error = NULL;
	gboolean wifi, net, wwan, wimax;

	g_return_val_if_fail (net_enabled != NULL, FALSE);
	g_return_val_if_fail (wifi_enabled != NULL, FALSE);
	g_return_val_if_fail (wwan_enabled != NULL, FALSE);
	g_return_val_if_fail (wimax_enabled != NULL, FALSE);

	state_file = g_key_file_new ();
	if (!state_file) {
		g_set_error (error, NM_CONFIG_ERROR, NM_CONFIG_ERROR_NO_MEMORY,
		             "Not enough memory to load state file %s.", filename);
		return FALSE;
	}

	g_key_file_set_list_separator (state_file, ',');
	if (!g_key_file_load_from_file (state_file, filename, G_KEY_FILE_KEEP_COMMENTS, &tmp_error)) {
		gboolean ret = FALSE;

		/* This is kinda ugly; create the file and directory if it doesn't
		 * exist yet.  We can't rely on distros necessarily creating the
		 * /var/lib/NetworkManager for us since we have to ensure that
		 * users upgrading NM get this working too.
		 */
		if (g_error_matches (tmp_error, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
			char *data, *dirname;
			gsize len = 0;

			g_clear_error (&tmp_error);

			/* try to create the directory if it doesn't exist */
			dirname = g_path_get_dirname (filename);
			errno = 0;
			if (g_mkdir_with_parents (dirname, 0755) != 0) {
				if (errno != EEXIST) {
					g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_ACCES,
					             "Error creating state directory %s: %s", dirname, strerror(errno));
					g_free (dirname);
					return FALSE;
				}
			}
			g_free (dirname);

			/* Write out the initial state to the state file */
			g_key_file_set_boolean (state_file, "main", "NetworkingEnabled", *net_enabled);
			g_key_file_set_boolean (state_file, "main", "WirelessEnabled", *wifi_enabled);
			g_key_file_set_boolean (state_file, "main", "WWANEnabled", *wwan_enabled);
			g_key_file_set_boolean (state_file, "main", "WimaxEnabled", *wimax_enabled);

			data = g_key_file_to_data (state_file, &len, NULL);
			if (data)
				ret = g_file_set_contents (filename, data, len, error);
			g_free (data);
		} else {
			/* the error is not "No such file or directory" - propagate the error */
			g_propagate_error (error, tmp_error);
		}

		return ret;
	}

	/* Reading state bits of NetworkManager; an error leaves the passed-in state
	 * value unchanged.
	 */
	net = g_key_file_get_boolean (state_file, "main", "NetworkingEnabled", &tmp_error);
	if (tmp_error == NULL)
		*net_enabled = net;
	g_clear_error (&tmp_error);

	wifi = g_key_file_get_boolean (state_file, "main", "WirelessEnabled", &tmp_error);
	if (tmp_error == NULL)
		*wifi_enabled = wifi;
	g_clear_error (&tmp_error);

	wwan = g_key_file_get_boolean (state_file, "main", "WWANEnabled", &tmp_error);
	if (tmp_error == NULL)
		*wwan_enabled = wwan;
	g_clear_error (&tmp_error);

	wimax = g_key_file_get_boolean (state_file, "main", "WimaxEnabled", &tmp_error);
	if (tmp_error == NULL)
		*wimax_enabled = wimax;
	g_clear_error (&tmp_error);

	g_key_file_free (state_file);
	return TRUE;
}

/*
 * main
 *
 */
int
main (int argc, char *argv[])
{
	GOptionContext *opt_ctx = NULL;
	gboolean become_daemon = FALSE;
	gboolean g_fatal_warnings = FALSE;
	char *pidfile = NULL, *state_file = NULL;
	char *config_path = NULL, *plugins = NULL;
	char *log_level = NULL, *log_domains = NULL;
	char *connectivity_uri = NULL;
	gint connectivity_interval = -1;
	char *connectivity_response = NULL;
	gboolean wifi_enabled = TRUE, net_enabled = TRUE, wwan_enabled = TRUE, wimax_enabled = TRUE;
	gboolean success, show_version = FALSE;
	NMPolicy *policy = NULL;
	NMVPNManager *vpn_manager = NULL;
	NMDnsManager *dns_mgr = NULL;
	NMDBusManager *dbus_mgr = NULL;
	NMSupplicantManager *sup_mgr = NULL;
	NMDHCPManager *dhcp_mgr = NULL;
	NMFirewallManager *fw_mgr = NULL;
	NMSettings *settings = NULL;
	NMConfig *config;
	NMNetlinkMonitor *monitor = NULL;
	GError *error = NULL;
	gboolean wrote_pidfile = FALSE;

	GOptionEntry options[] = {
		{ "version", 0, 0, G_OPTION_ARG_NONE, &show_version, N_("Print NetworkManager version and exit"), NULL },
		{ "no-daemon", 0, 0, G_OPTION_ARG_NONE, &become_daemon, N_("Don't become a daemon"), NULL },
		{ "g-fatal-warnings", 0, 0, G_OPTION_ARG_NONE, &g_fatal_warnings, N_("Make all warnings fatal"), NULL },
		{ "pid-file", 0, 0, G_OPTION_ARG_FILENAME, &pidfile, N_("Specify the location of a PID file"), N_("filename") },
		{ "state-file", 0, 0, G_OPTION_ARG_FILENAME, &state_file, N_("State file location"), N_("/path/to/state.file") },
		{ "config", 0, 0, G_OPTION_ARG_FILENAME, &config_path, N_("Config file location"), N_("/path/to/config.file") },
		{ "plugins", 0, 0, G_OPTION_ARG_STRING, &plugins, N_("List of plugins separated by ','"), N_("plugin1,plugin2") },
		/* Translators: Do not translate the values in the square brackets */
		{ "log-level", 0, 0, G_OPTION_ARG_STRING, &log_level, N_("Log level: one of [ERR, WARN, INFO, DEBUG]"), "INFO" },
		{ "log-domains", 0, 0, G_OPTION_ARG_STRING, &log_domains,
		        /* Translators: Do not translate the values in the square brackets */
		        N_("Log domains separated by ',': any combination of\n"
		        "                                          [NONE,HW,RFKILL,ETHER,WIFI,BT,MB,DHCP4,DHCP6,PPP,\n"
		        "                                           WIFI_SCAN,IP4,IP6,AUTOIP4,DNS,VPN,SHARING,SUPPLICANT,\n"
		        "                                           AGENTS,SETTINGS,SUSPEND,CORE,DEVICE,OLPC,WIMAX,\n"
		        "                                           INFINIBAND,FIREWALL]"),
		        "HW,RFKILL,WIFI" },
		{ "connectivity-uri", 0, 0, G_OPTION_ARG_STRING, &connectivity_uri, "A http(s) address to check internet connectivity" },
		{ "connectivity-interval", 0, 0, G_OPTION_ARG_INT, &connectivity_interval, "the interval in seconds how often a connectivity check will be done" },
		{ "connectivity-response", 0, 0, G_OPTION_ARG_STRING, &connectivity_response, "the expected start of the response" },
		{NULL}
	};

	if (!g_module_supported ()) {
		fprintf (stderr, _("GModules are not supported on your platform!\n"));
		exit (1);
	}

	/* Set up unix signal handling */
	if (!setup_signals ())
		exit (1);

	/* Set locale to be able to use environment variables */
	setlocale (LC_ALL, "");

	bindtextdomain (GETTEXT_PACKAGE, NMLOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	/* Parse options */
	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_translation_domain (opt_ctx, GETTEXT_PACKAGE);
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);

	g_option_context_set_summary (opt_ctx,
		_("NetworkManager monitors all network connections and automatically\nchooses the best connection to use.  It also allows the user to\nspecify wireless access points which wireless cards in the computer\nshould associate with."));

	success = g_option_context_parse (opt_ctx, &argc, &argv, NULL);
	g_option_context_free (opt_ctx);

	if (!success) {
		fprintf (stderr, _("Invalid option.  Please use --help to see a list of valid options.\n"));
		exit (1);
	}

	if (show_version) {
		fprintf (stdout, NM_DIST_VERSION "\n");
		exit (0);
	}

	if (getuid () != 0) {
		fprintf (stderr, _("You must be root to run NetworkManager!\n"));
		exit (1);
	}

	/* Make GIO ignore the remote VFS service; otherwise it tries to use the
	 * session bus to contact the remote service, and NM shouldn't ever be
	 * talking on the session bus.  See rh #588745
	 */
	setenv ("GIO_USE_VFS", "local", 1);

	pidfile = pidfile ? pidfile : g_strdup (NM_DEFAULT_PID_FILE);
	state_file = state_file ? state_file : g_strdup (NM_DEFAULT_SYSTEM_STATE_FILE);

	/* check pid file */
	if (check_pidfile (pidfile))
		exit (1);

	/* Read the config file and CLI overrides */
	config = nm_config_new (config_path, plugins, log_level, log_domains,
	                        connectivity_uri, connectivity_interval, connectivity_response, &error);
	if (config == NULL) {
		fprintf (stderr, _("Failed to read configuration: (%d) %s\n"),
		         error ? error->code : -1,
		         (error && error->message) ? error->message : _("unknown"));
		exit (1);
	}

	/* Logging setup */
	if (!nm_logging_setup (nm_config_get_log_level (config),
	                       nm_config_get_log_domains (config),
	                       &error)) {
		fprintf (stderr,
		         _("%s.  Please use --help to see a list of valid options.\n"),
		         error->message);
		exit (1);
	}

	/* Parse the state file */
	if (!parse_state_file (state_file, &net_enabled, &wifi_enabled, &wwan_enabled, &wimax_enabled, &error)) {
		fprintf (stderr, _("State file %s parsing failed: (%d) %s\n"),
		         state_file,
		         error ? error->code : -1,
		         (error && error->message) ? error->message : _("unknown"));
		/* Not a hard failure */
	}
	g_clear_error (&error);

	/* Tricky: become_daemon is FALSE by default, so unless it's TRUE because
	 * of a CLI option, it'll become TRUE after this
	 */
	become_daemon = !become_daemon;
	if (become_daemon) {
		if (daemon (0, 0) < 0) {
			int saved_errno;

			saved_errno = errno;
			fprintf (stderr, _("Could not daemonize: %s [error %u]\n"),
			         g_strerror (saved_errno),
			         saved_errno);
			exit (1);
		}
		if (write_pidfile (pidfile))
			wrote_pidfile = TRUE;
	}

	if (g_fatal_warnings) {
		GLogLevelFlags fatal_mask;

		fatal_mask = g_log_set_always_fatal (G_LOG_FATAL_MASK);
		fatal_mask |= G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL;
		g_log_set_always_fatal (fatal_mask);
	}

	/*
	 * Set the umask to 0022, which results in 0666 & ~0022 = 0644.
	 * Otherwise, if root (or an su'ing user) has a wacky umask, we could
	 * write out an unreadable resolv.conf.
	 */
	umask (022);

	g_type_init ();

/*
 * Threading is always enabled starting from GLib 2.31.0.
 * See also http://developer.gnome.org/glib/2.31/glib-Deprecated-Thread-APIs.html.
 */
#if !GLIB_CHECK_VERSION (2,31,0)
	if (!g_thread_supported ())
		g_thread_init (NULL);
	dbus_g_thread_init ();
#else
	dbus_threads_init_default ();
#endif

#ifndef HAVE_DBUS_GLIB_DISABLE_LEGACY_PROP_ACCESS
#error HAVE_DBUS_GLIB_DISABLE_LEGACY_PROP_ACCESS not defined
#endif

#if HAVE_DBUS_GLIB_DISABLE_LEGACY_PROP_ACCESS
	/* Ensure that non-exported properties don't leak out, and that the
	 * introspection 'access' permissions are respected.
	 */
	dbus_glib_global_set_disable_legacy_property_access ();
#endif

	nm_logging_start (become_daemon);

	nm_log_info (LOGD_CORE, "NetworkManager (version " NM_DIST_VERSION ") is starting...");
	success = FALSE;

	nm_log_info (LOGD_CORE, "Read config file %s", nm_config_get_path (config));
	nm_log_info (LOGD_CORE, "WEXT support is %s",
#if HAVE_WEXT
	             "enabled"
#else
	             "disabled"
#endif
	             );

	main_loop = g_main_loop_new (NULL, FALSE);

	/* Create netlink monitor object */
	monitor = nm_netlink_monitor_get ();

	/* Initialize our DBus service & connection */
	dbus_mgr = nm_dbus_manager_get ();

	vpn_manager = nm_vpn_manager_get ();
	if (!vpn_manager) {
		nm_log_err (LOGD_CORE, "failed to start the VPN manager.");
		goto done;
	}

	dns_mgr = nm_dns_manager_get (nm_config_get_dns_plugins (config));
	if (!dns_mgr) {
		nm_log_err (LOGD_CORE, "failed to start the DNS manager.");
		goto done;
	}

	settings = nm_settings_new (nm_config_get_path (config),
	                            nm_config_get_plugins (config),
	                            &error);
	if (!settings) {
		nm_log_err (LOGD_CORE, "failed to initialize settings storage: %s",
		            error && error->message ? error->message : "(unknown)");
		goto done;
	}

	manager = nm_manager_new (settings,
	                          state_file,
	                          net_enabled,
	                          wifi_enabled,
	                          wwan_enabled,
	                          wimax_enabled,
	                          nm_config_get_connectivity_uri (config),
	                          nm_config_get_connectivity_interval (config),
	                          nm_config_get_connectivity_response (config),
	                          &error);
	if (manager == NULL) {
		nm_log_err (LOGD_CORE, "failed to initialize the network manager: %s",
		            error && error->message ? error->message : "(unknown)");
		goto done;
	}

	policy = nm_policy_new (manager, vpn_manager, settings);
	if (policy == NULL) {
		nm_log_err (LOGD_CORE, "failed to initialize the policy.");
		goto done;
	}

	/* Initialize the supplicant manager */
	sup_mgr = nm_supplicant_manager_get ();
	if (!sup_mgr) {
		nm_log_err (LOGD_CORE, "failed to initialize the supplicant manager.");
		goto done;
	}

	/* Initialize DHCP manager */
	dhcp_mgr = nm_dhcp_manager_new (nm_config_get_dhcp_client (config), &error);
	if (!dhcp_mgr) {
		nm_log_err (LOGD_CORE, "failed to start the DHCP manager: %s.", error->message);
		goto done;
	}

	nm_dhcp_manager_set_hostname_provider (dhcp_mgr, NM_HOSTNAME_PROVIDER (manager));

	/* Initialize Firewall manager */
	fw_mgr = nm_firewall_manager_get ();
	if (!fw_mgr) {
		nm_log_err (LOGD_CORE, "failed to start the Firewall manager: %s.", error->message);
		goto done;
	}

	/* Start our DBus service */
	if (!nm_dbus_manager_start_service (dbus_mgr)) {
		nm_log_err (LOGD_CORE, "failed to start the dbus service.");
		goto done;
	}

	/* Clean leftover "# Added by NetworkManager" entries from /etc/hosts */
	nm_policy_hosts_clean_etc_hosts ();

	nm_manager_start (manager);

	/* Bring up the loopback interface. */
	nm_backend_enable_loopback ();

	success = TRUE;

	/* Told to quit before getting to the mainloop by the signal handler */
	if (quit_early == TRUE)
		goto done;

	g_main_loop_run (main_loop);

done:
	if (policy)
		nm_policy_destroy (policy);

	if (manager)
		g_object_unref (manager);

	if (settings)
		g_object_unref (settings);

	if (vpn_manager)
		g_object_unref (vpn_manager);

	if (dns_mgr)
		g_object_unref (dns_mgr);

	if (dhcp_mgr)
		g_object_unref (dhcp_mgr);

	if (sup_mgr)
		g_object_unref (sup_mgr);

	if (fw_mgr)
		g_object_unref (fw_mgr);

	if (dbus_mgr)
		g_object_unref (dbus_mgr);

	nm_logging_shutdown ();

	if (pidfile && wrote_pidfile)
		unlink (pidfile);

	nm_config_free (config);

	/* Free options */
	g_free (pidfile);
	g_free (state_file);
	g_free (config_path);
	g_free (plugins);
	g_free (log_level);
	g_free (log_domains);
	g_free (connectivity_uri);
	g_free (connectivity_response);

	nm_log_info (LOGD_CORE, "exiting (%s)", success ? "success" : "error");
	exit (success ? 0 : 1);
}
