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
 * Copyright (C) 2004 - 2017 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#include "nm-default.h"

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
#include <string.h>
#include <sys/resource.h>

#include "main-utils.h"
#include "nm-dbus-interface.h"
#include "NetworkManagerUtils.h"
#include "nm-manager.h"
#include "platform/nm-linux-platform.h"
#include "nm-dbus-manager.h"
#include "devices/nm-device.h"
#include "dhcp/nm-dhcp-manager.h"
#include "nm-config.h"
#include "nm-session-monitor.h"
#include "nm-dispatcher.h"
#include "settings/nm-settings.h"
#include "nm-auth-manager.h"
#include "nm-core-internal.h"
#include "nm-dbus-object.h"
#include "nm-connectivity.h"
#include "dns/nm-dns-manager.h"
#include "systemd/nm-sd.h"
#include "nm-netns.h"

#if !defined(NM_DIST_VERSION)
# define NM_DIST_VERSION VERSION
#endif

#define NM_DEFAULT_PID_FILE          NMRUNDIR "/NetworkManager.pid"
#define NM_DEFAULT_SYSTEM_STATE_FILE NMSTATEDIR "/NetworkManager.state"

#define CONFIG_ATOMIC_SECTION_PREFIXES ((char **) NULL)

static GMainLoop *main_loop = NULL;
static gboolean configure_and_quit = FALSE;

static struct {
	gboolean show_version;
	gboolean print_config;
	gboolean become_daemon;
	gboolean g_fatal_warnings;
	gboolean run_from_build_dir;
	char *opt_log_level;
	char *opt_log_domains;
	char *pidfile;
} global_opt = {
	.become_daemon = TRUE,
};

static void
_set_g_fatal_warnings (void)
{
	GLogLevelFlags fatal_mask;

	fatal_mask = g_log_set_always_fatal (G_LOG_FATAL_MASK);
	fatal_mask |= G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL;
	g_log_set_always_fatal (fatal_mask);
}

static void
_init_nm_debug (NMConfig *config)
{
	gs_free char *debug = NULL;
	enum {
		D_RLIMIT_CORE =    (1 << 0),
		D_FATAL_WARNINGS = (1 << 1),
	};
	GDebugKey keys[] = {
		{ "RLIMIT_CORE", D_RLIMIT_CORE },
		{ "fatal-warnings", D_FATAL_WARNINGS },
	};
	guint flags;
	const char *env = getenv ("NM_DEBUG");

	debug = nm_config_data_get_value (nm_config_get_data_orig (config),
	                                  NM_CONFIG_KEYFILE_GROUP_MAIN,
	                                  NM_CONFIG_KEYFILE_KEY_MAIN_DEBUG,
	                                  NM_MANAGER_RELOAD_FLAGS_NONE);

	flags  = nm_utils_parse_debug_string (env, keys, G_N_ELEMENTS (keys));
	flags |= nm_utils_parse_debug_string (debug, keys, G_N_ELEMENTS (keys));

#if ! defined (__SANITIZE_ADDRESS__)
	if (NM_FLAGS_HAS (flags, D_RLIMIT_CORE)) {
		/* only enable this, if explicitly requested, because it might
		 * expose sensitive data. */

		struct rlimit limit = {
			.rlim_cur = RLIM_INFINITY,
			.rlim_max = RLIM_INFINITY,
		};
		setrlimit (RLIMIT_CORE, &limit);
	}
#endif

	if (NM_FLAGS_HAS (flags, D_FATAL_WARNINGS))
		_set_g_fatal_warnings ();
}

void
nm_main_config_reload (int signal)
{
	NMConfigChangeFlags reload_flags;

	switch (signal) {
	case SIGHUP:
		reload_flags = NM_CONFIG_CHANGE_CAUSE_SIGHUP;
		break;
	case SIGUSR1:
		reload_flags = NM_CONFIG_CHANGE_CAUSE_SIGUSR1;
		break;
	case SIGUSR2:
		reload_flags = NM_CONFIG_CHANGE_CAUSE_SIGUSR2;
		break;
	default:
		g_return_if_reached ();
	}

	nm_log_info (LOGD_CORE, "reload configuration (signal %s)...", strsignal (signal));

	/* The signal handler thread is only installed after
	 * creating NMConfig instance, and on shut down we
	 * no longer run the mainloop (to reach this point).
	 *
	 * Hence, a NMConfig singleton instance must always be
	 * available. */
	nm_config_reload (nm_config_get (), reload_flags);
}

static void
manager_configure_quit (NMManager *manager, gpointer user_data)
{
	nm_log_info (LOGD_CORE, "quitting now that startup is complete");
	g_main_loop_quit (main_loop);
	configure_and_quit = TRUE;
}

static int
print_config (NMConfigCmdLineOptions *config_cli)
{
	gs_unref_object NMConfig *config = NULL;
	gs_free_error GError *error = NULL;
	NMConfigData *config_data;

	nm_logging_setup ("OFF", "ALL", NULL, NULL);

	config = nm_config_new (config_cli, CONFIG_ATOMIC_SECTION_PREFIXES, &error);
	if (config == NULL) {
		fprintf (stderr, _("Failed to read configuration: %s\n"), error->message);
		return 7;
	}

	config_data = nm_config_get_data (config);
	fprintf (stdout, "# NetworkManager configuration: %s\n", nm_config_data_get_config_description (config_data));
	nm_config_data_log (config_data, "", "", stdout);
	return 0;
}

static void
do_early_setup (int *argc, char **argv[], NMConfigCmdLineOptions *config_cli)
{
	GOptionEntry options[] = {
		{ "version", 'V', 0, G_OPTION_ARG_NONE, &global_opt.show_version, N_("Print NetworkManager version and exit"), NULL },
		{ "no-daemon", 'n', G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, &global_opt.become_daemon, N_("Don't become a daemon"), NULL },
		{ "log-level", 0, 0, G_OPTION_ARG_STRING, &global_opt.opt_log_level, N_("Log level: one of [%s]"), "INFO" },
		{ "log-domains", 0, 0, G_OPTION_ARG_STRING, &global_opt.opt_log_domains,
		  N_("Log domains separated by ',': any combination of [%s]"),
		  "PLATFORM,RFKILL,WIFI" },
		{ "g-fatal-warnings", 0, 0, G_OPTION_ARG_NONE, &global_opt.g_fatal_warnings, N_("Make all warnings fatal"), NULL },
		{ "pid-file", 'p', 0, G_OPTION_ARG_FILENAME, &global_opt.pidfile, N_("Specify the location of a PID file"), NM_DEFAULT_PID_FILE },
		{ "run-from-build-dir", 0, 0, G_OPTION_ARG_NONE, &global_opt.run_from_build_dir, "Run from build directory", NULL },
		{ "print-config", 0, 0, G_OPTION_ARG_NONE, &global_opt.print_config, N_("Print NetworkManager configuration and exit"), NULL },
		{NULL}
	};

	if (!nm_main_utils_early_setup ("NetworkManager",
	                                argc,
	                                argv,
	                                options,
	                                (void (*)(gpointer, GOptionContext *)) nm_config_cmd_line_options_add_to_entries,
	                                config_cli,
	                                _("NetworkManager monitors all network connections and automatically\nchooses the best connection to use.  It also allows the user to\nspecify wireless access points which wireless cards in the computer\nshould associate with.")))
		exit (1);

	global_opt.pidfile = global_opt.pidfile ?: g_strdup(NM_DEFAULT_PID_FILE);
}

/*
 * main
 *
 */
int
main (int argc, char *argv[])
{
	gboolean success = FALSE;
	NMManager *manager = NULL;
	NMConfig *config;
	gs_free_error GError *error = NULL;
	gboolean wrote_pidfile = FALSE;
	char *bad_domains = NULL;
	NMConfigCmdLineOptions *config_cli;
	guint sd_id = 0;
	GError *error_invalid_logging_config = NULL;

	/* Known to cause a possible deadlock upon GDBus initialization:
	 * https://bugzilla.gnome.org/show_bug.cgi?id=674885 */
	g_type_ensure (G_TYPE_SOCKET);
	g_type_ensure (G_TYPE_DBUS_CONNECTION);
	g_type_ensure (NM_TYPE_DBUS_MANAGER);

	_nm_utils_is_manager_process = TRUE;

	main_loop = g_main_loop_new (NULL, FALSE);

	/* we determine a first-start (contrary to a restart during the same boot)
	 * based on the existence of NM_CONFIG_DEVICE_STATE_DIR directory. */
	config_cli = nm_config_cmd_line_options_new (!g_file_test (NM_CONFIG_DEVICE_STATE_DIR,
	                                                           G_FILE_TEST_IS_DIR));

	do_early_setup (&argc, &argv, config_cli);

	if (global_opt.g_fatal_warnings)
		_set_g_fatal_warnings ();

	if (global_opt.show_version) {
		fprintf (stdout, NM_DIST_VERSION "\n");
		exit (0);
	}

	if (global_opt.print_config) {
		int result;

		result = print_config (config_cli);
		nm_config_cmd_line_options_free (config_cli);
		exit (result);
	}

	nm_main_utils_ensure_root ();

	nm_main_utils_ensure_not_running_pidfile (global_opt.pidfile);

	nm_main_utils_ensure_statedir ();
	nm_main_utils_ensure_rundir ();

	/* When running from the build directory, determine our build directory
	 * base and set helper paths in the build tree */
	if (global_opt.run_from_build_dir) {
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
		nm_dhcp_helper_path = g_strdup_printf ("%s/src/dhcp/nm-dhcp-helper", path);

		g_free (path);
	}

	if (!nm_logging_setup (global_opt.opt_log_level,
	                       global_opt.opt_log_domains,
	                       &bad_domains,
	                       &error)) {
		fprintf (stderr,
		         _("%s.  Please use --help to see a list of valid options.\n"),
		         error->message);
		exit (1);
	}

	/* Read the config file and CLI overrides */
	config = nm_config_setup (config_cli, CONFIG_ATOMIC_SECTION_PREFIXES, &error);
	nm_config_cmd_line_options_free (config_cli);
	config_cli = NULL;
	if (config == NULL) {
		fprintf (stderr, _("Failed to read configuration: %s\n"),
		         error->message);
		exit (1);
	}

	_init_nm_debug (config);

	/* Initialize logging from config file *only* if not explicitly
	 * specified by commandline.
	 */
	if (global_opt.opt_log_level == NULL && global_opt.opt_log_domains == NULL) {
		if (!nm_logging_setup (nm_config_get_log_level (config),
		                       nm_config_get_log_domains (config),
		                       &bad_domains,
		                       &error_invalid_logging_config)) {
			/* ignore error, and print the failure reason below.
			 * Likewise, print about bad_domains below. */
		}
	}

	if (global_opt.become_daemon && !nm_config_get_is_debug (config)) {
		if (daemon (0, 0) < 0) {
			int saved_errno;

			saved_errno = errno;
			fprintf (stderr, _("Could not daemonize: %s [error %u]\n"),
			         g_strerror (saved_errno),
			         saved_errno);
			exit (1);
		}
		wrote_pidfile = nm_main_utils_write_pidfile (global_opt.pidfile);
	}

	/* Set up unix signal handling - before creating threads, but after daemonizing! */
	nm_main_utils_setup_signals (main_loop);

	{
		gs_free char *v = NULL;

		v = nm_config_data_get_value (NM_CONFIG_GET_DATA_ORIG,
		                              NM_CONFIG_KEYFILE_GROUP_LOGGING,
		                              NM_CONFIG_KEYFILE_KEY_LOGGING_BACKEND,
		                              NM_CONFIG_GET_VALUE_STRIP | NM_CONFIG_GET_VALUE_NO_EMPTY);
		nm_logging_syslog_openlog (v, nm_config_get_is_debug (config));
	}

	nm_log_info (LOGD_CORE, "NetworkManager (version " NM_DIST_VERSION ") is starting... (%s)",
	             nm_config_get_first_start (config) ? "for the first time" : "after a restart");

	nm_log_info (LOGD_CORE, "Read config: %s", nm_config_data_get_config_description (nm_config_get_data (config)));
	nm_config_data_log (nm_config_get_data (config), "CONFIG: ", "  ", NULL);

	if (error_invalid_logging_config) {
		nm_log_warn (LOGD_CORE, "config: invalid logging configuration: %s", error_invalid_logging_config->message);
		g_clear_error (&error_invalid_logging_config);
	}
	if (bad_domains) {
		nm_log_warn (LOGD_CORE, "config: invalid logging domains '%s' from %s",
		             bad_domains,
		             (global_opt.opt_log_level == NULL && global_opt.opt_log_domains == NULL)
		               ? "config file"
		               : "command line");
		nm_clear_g_free (&bad_domains);
	}

	/* the first access to State causes the file to be read (and possibly print a warning) */
	nm_config_state_get (config);

	nm_log_dbg (LOGD_CORE, "WEXT support is %s",
#if HAVE_WEXT
	             "enabled"
#else
	             "disabled"
#endif
	             );

	/* Set up platform interaction layer */
	nm_linux_platform_setup ();

	NM_UTILS_KEEP_ALIVE (config, nm_netns_get (), "NMConfig-depends-on-NMNetns");

	nm_auth_manager_setup (nm_config_data_get_value_boolean (nm_config_get_data_orig (config),
	                                                         NM_CONFIG_KEYFILE_GROUP_MAIN,
	                                                         NM_CONFIG_KEYFILE_KEY_MAIN_AUTH_POLKIT,
	                                                         NM_CONFIG_DEFAULT_MAIN_AUTH_POLKIT_BOOL));

	if (!nm_dbus_manager_acquire_bus (nm_dbus_manager_get ()))
		goto done_no_manager;

	manager = nm_manager_setup ();
	nm_dbus_manager_start (nm_dbus_manager_get(),
	                       nm_manager_dbus_set_property_handle,
	                       manager);

	nm_dispatcher_init ();

	g_signal_connect (manager, NM_MANAGER_CONFIGURE_QUIT, G_CALLBACK (manager_configure_quit), config);

	if (!nm_manager_start (manager, &error)) {
		nm_log_err (LOGD_CORE, "failed to initialize: %s", error->message);
		goto done;
	}

	nm_platform_process_events (NM_PLATFORM_GET);

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
	nm_platform_link_set_up (NM_PLATFORM_GET, 1, NULL);

	success = TRUE;

	if (configure_and_quit == FALSE) {
		sd_id = nm_sd_event_attach_default ();

		g_main_loop_run (main_loop);
	}

done:

	/* write the device-state to file. Note that we only persist the
	 * state here. We don't bother updating the state as devices
	 * change during regular operation. If NM is killed with SIGKILL,
	 * it misses to update the state. */
	nm_manager_write_device_state (manager);

	nm_manager_stop (manager);

	nm_config_state_set (config, TRUE, TRUE);

	nm_dns_manager_stop (nm_dns_manager_get ());

done_no_manager:
	if (global_opt.pidfile && wrote_pidfile)
		unlink (global_opt.pidfile);

	nm_log_info (LOGD_CORE, "exiting (%s)", success ? "success" : "error");

	nm_clear_g_source (&sd_id);

	exit (success ? 0 : 1);
}
