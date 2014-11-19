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
#include <sys/resource.h>

#include "gsystem-local-alloc.h"
#include "nm-dbus-interface.h"
#include "NetworkManagerUtils.h"
#include "main-utils.h"
#include "nm-manager.h"
#include "nm-linux-platform.h"
#include "nm-dns-manager.h"
#include "nm-dbus-manager.h"
#include "nm-supplicant-manager.h"
#include "nm-dhcp-manager.h"
#include "nm-firewall-manager.h"
#include "nm-vpn-manager.h"
#include "nm-logging.h"
#include "nm-config.h"
#include "nm-posix-signals.h"
#include "nm-session-monitor.h"
#include "nm-dispatcher.h"
#include "nm-settings.h"
#include "nm-auth-manager.h"
#include "nm-core-internal.h"

#if !defined(NM_DIST_VERSION)
# define NM_DIST_VERSION VERSION
#endif

#define NM_DEFAULT_PID_FILE          NMRUNDIR "/NetworkManager.pid"
#define NM_DEFAULT_SYSTEM_STATE_FILE NMSTATEDIR "/NetworkManager.state"

static GMainLoop *main_loop = NULL;

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
	g_key_file_set_list_separator (state_file, ',');
	if (!g_key_file_load_from_file (state_file, filename, G_KEY_FILE_KEEP_COMMENTS, &tmp_error)) {
		gboolean ret = FALSE;

		/* This is kinda ugly; create the file and directory if it doesn't
		 * exist yet.  We can't rely on distros necessarily creating the
		 * /var/lib/NetworkManager for us since we have to ensure that
		 * users upgrading NM get this working too.
		 */
		if (g_error_matches (tmp_error, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
			char *data;
			gsize len = 0;

			g_clear_error (&tmp_error);

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

static void
_init_nm_debug (const char *debug)
{
	const guint D_RLIMIT_CORE = 1;
	GDebugKey keys[] = {
		{ "RLIMIT_CORE", D_RLIMIT_CORE },
	};
	guint flags = 0;
	const char *env = getenv ("NM_DEBUG");

	if (env && strcasecmp (env, "help") != 0) {
		/* g_parse_debug_string() prints options to stderr if the variable
		 * is set to "help". Don't allow that. */
		flags = g_parse_debug_string (env,  keys, G_N_ELEMENTS (keys));
	}

	if (debug && strcasecmp (debug, "help") != 0)
		flags |= g_parse_debug_string (debug,  keys, G_N_ELEMENTS (keys));

	if (flags & D_RLIMIT_CORE) {
		/* only enable this, if explicitly requested, because it might
		 * expose sensitive data. */

		struct rlimit limit = {
			.rlim_cur = RLIM_INFINITY,
			.rlim_max = RLIM_INFINITY,
		};
		setrlimit (RLIMIT_CORE, &limit);
	}
}

static void
manager_configure_quit (NMManager *manager, gpointer user_data)
{
	nm_log_info (LOGD_CORE, "quitting now that startup is complete");
	g_main_loop_quit (main_loop);
}

/*
 * main
 *
 */
int
main (int argc, char *argv[])
{
	char *opt_log_level = NULL;
	char *opt_log_domains = NULL;
	gboolean become_daemon = TRUE, run_from_build_dir = FALSE;
	gboolean debug = FALSE;
	gboolean g_fatal_warnings = FALSE;
	gs_free char *pidfile = NULL;
	gs_free char *state_file = NULL;
	gboolean wifi_enabled = TRUE, net_enabled = TRUE, wwan_enabled = TRUE, wimax_enabled = TRUE;
	gboolean success, show_version = FALSE;
	NMManager *manager = NULL;
	gs_unref_object NMVpnManager *vpn_manager = NULL;
	gs_unref_object NMDnsManager *dns_mgr = NULL;
	gs_unref_object NMDBusManager *dbus_mgr = NULL;
	gs_unref_object NMSupplicantManager *sup_mgr = NULL;
	gs_unref_object NMDhcpManager *dhcp_mgr = NULL;
	gs_unref_object NMFirewallManager *fw_mgr = NULL;
	gs_unref_object NMSettings *settings = NULL;
	gs_unref_object NMConfig *config = NULL;
	gs_unref_object NMSessionMonitor *session_monitor = NULL;
	GError *error = NULL;
	gboolean wrote_pidfile = FALSE;
	char *bad_domains = NULL;
	gboolean quit_early = FALSE;

	GOptionEntry options[] = {
		{ "version", 'V', 0, G_OPTION_ARG_NONE, &show_version, N_("Print NetworkManager version and exit"), NULL },
		{ "no-daemon", 'n', G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, &become_daemon, N_("Don't become a daemon"), NULL },
		{ "debug", 'd', 0, G_OPTION_ARG_NONE, &debug, N_("Don't become a daemon, and log to stderr"), NULL },
		{ "log-level", 0, 0, G_OPTION_ARG_STRING, &opt_log_level, N_("Log level: one of [%s]"), "INFO" },
		{ "log-domains", 0, 0, G_OPTION_ARG_STRING, &opt_log_domains,
		  N_("Log domains separated by ',': any combination of [%s]"),
		  "PLATFORM,RFKILL,WIFI" },
		{ "g-fatal-warnings", 0, 0, G_OPTION_ARG_NONE, &g_fatal_warnings, N_("Make all warnings fatal"), NULL },
		{ "pid-file", 'p', 0, G_OPTION_ARG_FILENAME, &pidfile, N_("Specify the location of a PID file"), N_("filename") },
		{ "state-file", 0, 0, G_OPTION_ARG_FILENAME, &state_file, N_("State file location"), N_("/path/to/state.file") },
		{ "run-from-build-dir", 0, 0, G_OPTION_ARG_NONE, &run_from_build_dir, "Run from build directory", NULL },
		{NULL}
	};

	_nm_utils_is_manager_process = TRUE;

	main_loop = g_main_loop_new (NULL, FALSE);

	if (!nm_main_utils_early_setup ("NetworkManager",
	                                &argv,
	                                &argc,
	                                options,
	                                nm_config_get_options (),
	                                _("NetworkManager monitors all network connections and automatically\nchooses the best connection to use.  It also allows the user to\nspecify wireless access points which wireless cards in the computer\nshould associate with.")))
		exit (1);

	if (show_version) {
		fprintf (stdout, NM_DIST_VERSION "\n");
		exit (0);
	}

	if (!nm_logging_setup (opt_log_level,
	                       opt_log_domains,
	                       &bad_domains,
	                       &error)) {
		fprintf (stderr,
		         _("%s.  Please use --help to see a list of valid options.\n"),
		         error->message);
		exit (1);
	} else if (bad_domains) {
		fprintf (stderr,
		         _("Ignoring unrecognized log domain(s) '%s' passed on command line.\n"),
		         bad_domains);
		g_clear_pointer (&bad_domains, g_free);
	}

	/* When running from the build directory, determine our build directory
	 * base and set helper paths in the build tree */
	if (run_from_build_dir) {
		char *path, *slash;
		int g;

		/* exe is <basedir>/src/.libs/lt-NetworkManager, so chop off
		 * the last three components */
		path = realpath ("/proc/self/exe", NULL);
		g_assert (path != NULL);
		for (g = 0; g < 3; ++g) {
			slash = strrchr (path, '/');
			g_assert (slash != NULL);
			*slash = '\0';
		}

		/* don't free these strings, we need them for the entire
		 * process lifetime */
		nm_dhcp_helper_path = g_strdup_printf ("%s/src/dhcp-manager/nm-dhcp-helper", path);
		nm_device_autoipd_helper_path = g_strdup_printf ("%s/callouts/nm-avahi-autoipd.action", path);

		g_free (path);
	}

	/* Ensure state directory exists */
	if (g_mkdir_with_parents (NMSTATEDIR, 0755) != 0) {
		nm_log_err (LOGD_CORE, "Cannot create '%s': %s", NMSTATEDIR, strerror (errno));
		exit (1);
	}

	pidfile = pidfile ? pidfile : g_strdup (NM_DEFAULT_PID_FILE);
	state_file = state_file ? state_file : g_strdup (NM_DEFAULT_SYSTEM_STATE_FILE);

	/* check pid file */
	if (nm_main_utils_check_pidfile (pidfile, "NetworkManager"))
		exit (1);

	/* Read the config file and CLI overrides */
	config = nm_config_new (&error);
	if (config == NULL) {
		fprintf (stderr, _("Failed to read configuration: (%d) %s\n"),
		         error ? error->code : -1,
		         (error && error->message) ? error->message : _("unknown"));
		exit (1);
	}

	/* Initialize logging from config file *only* if not explicitly
	 * specified by commandline.
	 */
	if (opt_log_level == NULL && opt_log_domains == NULL) {
		if (!nm_logging_setup (nm_config_get_log_level (config),
		                       nm_config_get_log_domains (config),
		                       &bad_domains,
		                       &error)) {
			fprintf (stderr, _("Error in configuration file: %s.\n"),
			         error->message);
			exit (1);
		} else if (bad_domains) {
			fprintf (stderr,
			         _("Ignoring unrecognized log domain(s) '%s' from config files.\n"),
			         bad_domains);
			g_clear_pointer (&bad_domains, g_free);
		}
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

	if (become_daemon && !debug) {
		if (daemon (0, 0) < 0) {
			int saved_errno;

			saved_errno = errno;
			fprintf (stderr, _("Could not daemonize: %s [error %u]\n"),
			         g_strerror (saved_errno),
			         saved_errno);
			exit (1);
		}
		wrote_pidfile = nm_main_utils_write_pidfile (pidfile);
	}

	_init_nm_debug (nm_config_get_debug (config));

	/* Set up unix signal handling - before creating threads, but after daemonizing! */
	if (!nm_main_utils_setup_signals (main_loop, &quit_early))
		exit (1);

	if (g_fatal_warnings) {
		GLogLevelFlags fatal_mask;

		fatal_mask = g_log_set_always_fatal (G_LOG_FATAL_MASK);
		fatal_mask |= G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL;
		g_log_set_always_fatal (fatal_mask);
	}

	nm_logging_syslog_openlog (debug);

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	dbus_threads_init_default ();

	/* Ensure that non-exported properties don't leak out, and that the
	 * introspection 'access' permissions are respected.
	 */
	dbus_glib_global_set_disable_legacy_property_access ();

	nm_log_info (LOGD_CORE, "NetworkManager (version " NM_DIST_VERSION ") is starting...");
	success = FALSE;

	nm_log_info (LOGD_CORE, "Read config: %s", nm_config_get_description (config));
	nm_log_info (LOGD_CORE, "WEXT support is %s",
#if HAVE_WEXT
	             "enabled"
#else
	             "disabled"
#endif
	             );

	/* Set up platform interaction layer */
	nm_linux_platform_setup ();

	nm_auth_manager_setup (nm_config_get_auth_polkit (config));

	/* Initialize our DBus service & connection */
	dbus_mgr = nm_dbus_manager_get ();
	g_assert (dbus_mgr != NULL);

	vpn_manager = nm_vpn_manager_get ();
	g_assert (vpn_manager != NULL);

	dns_mgr = nm_dns_manager_get ();
	g_assert (dns_mgr != NULL);

	/* Initialize DHCP manager */
	dhcp_mgr = nm_dhcp_manager_get ();
	g_assert (dhcp_mgr != NULL);

	nm_dispatcher_init ();

	settings = nm_settings_new (&error);
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
	                          &error);
	if (manager == NULL) {
		nm_log_err (LOGD_CORE, "failed to initialize the network manager: %s",
		            error && error->message ? error->message : "(unknown)");
		goto done;
	}

	/* Initialize the supplicant manager */
	sup_mgr = nm_supplicant_manager_get ();
	g_assert (sup_mgr != NULL);

	/* Initialize Firewall manager */
	fw_mgr = nm_firewall_manager_get ();
	g_assert (fw_mgr != NULL);

	/* Initialize session monitor */
	session_monitor = nm_session_monitor_get ();
	g_assert (session_monitor != NULL);

	if (!nm_dbus_manager_get_connection (dbus_mgr)) {
#if HAVE_DBUS_GLIB_100
		nm_log_warn (LOGD_CORE, "Failed to connect to D-Bus; only private bus is available");
#else
		nm_log_err (LOGD_CORE, "Failed to connect to D-Bus, exiting...");
		goto done;
#endif
	} else {
		/* Start our DBus service */
		if (!nm_dbus_manager_start_service (dbus_mgr)) {
			nm_log_err (LOGD_CORE, "failed to start the dbus service.");
			goto done;
		}
	}

	g_signal_connect (manager, NM_MANAGER_CONFIGURE_QUIT, G_CALLBACK (manager_configure_quit), config);

	nm_manager_start (manager);

	/* Make sure the loopback interface is up. If interface is down, we bring
	 * it up and kernel will assign it link-local IPv4 and IPv6 addresses. If
	 * it was already up, we assume is in clean state.
	 *
	 * TODO: it might be desirable to check the list of addresses and compare
	 * it with a list of expected addresses (one of the protocol families
	 * could be disabled). The 'lo' interface is sometimes used for assigning
	 * global addresses so their availability doesn't depend on the state of
	 * physical interfaces.
	 */
	nm_log_dbg (LOGD_CORE, "setting up local loopback");
	nm_platform_link_set_up (nm_platform_link_get_ifindex ("lo"));

	success = TRUE;

	/* Told to quit before getting to the mainloop by the signal handler */
	if (!quit_early)
		g_main_loop_run (main_loop);

	nm_manager_stop (manager);

done:
	g_clear_object (&manager);

	nm_logging_syslog_closelog ();

	if (pidfile && wrote_pidfile)
		unlink (pidfile);

	nm_log_info (LOGD_CORE, "exiting (%s)", success ? "success" : "error");
	exit (success ? 0 : 1);
}
