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
 * Copyright (C) 2004 - 2010 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
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
#include <gmodule.h>
#include <string.h>

#include "NetworkManager.h"
#include "NetworkManagerUtils.h"
#include "nm-manager.h"
#include "nm-policy.h"
#include "nm-system.h"
#include "nm-named-manager.h"
#include "nm-dbus-manager.h"
#include "nm-supplicant-manager.h"
#include "nm-dhcp-manager.h"
#include "nm-hostname-provider.h"
#include "nm-netlink-monitor.h"
#include "nm-vpn-manager.h"
#include "nm-logging.h"

#if !defined(NM_DIST_VERSION)
# define NM_DIST_VERSION VERSION
#endif

#define NM_DEFAULT_PID_FILE          LOCALSTATEDIR"/run/NetworkManager.pid"
#define NM_DEFAULT_SYSTEM_CONF_FILE  SYSCONFDIR"/NetworkManager/NetworkManager.conf"
#define NM_OLD_SYSTEM_CONF_FILE      SYSCONFDIR"/NetworkManager/nm-system-settings.conf"
#define NM_DEFAULT_SYSTEM_STATE_FILE LOCALSTATEDIR"/lib/NetworkManager/NetworkManager.state"

/*
 * Globals
 */
static NMManager *manager = NULL;
static GMainLoop *main_loop = NULL;

typedef struct {
	time_t time;
	GQuark domain;
	guint32 code;
	guint32 count;
} MonitorInfo;

static gboolean
detach_monitor (gpointer data)
{
	nm_log_warn (LOGD_HW, "detaching netlink event monitor");
	nm_netlink_monitor_detach (NM_NETLINK_MONITOR (data));
	return FALSE;
}

static void
nm_error_monitoring_device_link_state (NMNetlinkMonitor *monitor,
									   GError *error,
									   gpointer user_data)
{
	MonitorInfo *info = (MonitorInfo *) user_data;
	time_t now;

	now = time (NULL);

	if (   (info->domain != error->domain)
	    || (info->code != error->code)
	    || (info->time && now > info->time + 10)) {
		/* FIXME: Try to handle the error instead of just printing it. */
		nm_log_warn (LOGD_HW, "error monitoring device for netlink events: %s\n", error->message);

		info->time = now;
		info->domain = error->domain;
		info->code = error->code;
		info->count = 0;
	}

	info->count++;
	if (info->count > 100) {
		/* Broken drivers will sometimes cause a flood of netlink errors.
		 * rh #459205, novell #443429, lp #284507
		 */
		nm_log_warn (LOGD_HW, "excessive netlink errors ocurred, disabling netlink monitor.");
		nm_log_warn (LOGD_HW, "link change events will not be processed.");
		g_idle_add_full (G_PRIORITY_HIGH, detach_monitor, monitor, NULL);
	}
}

static gboolean
nm_monitor_setup (GError **error)
{
	NMNetlinkMonitor *monitor;
	MonitorInfo *info;

	monitor = nm_netlink_monitor_get ();
	if (!nm_netlink_monitor_open_connection (monitor, error)) {
		g_object_unref (monitor);
		return FALSE;
	}

	info = g_new0 (MonitorInfo, 1);
	g_signal_connect_data (G_OBJECT (monitor), "error",
						   G_CALLBACK (nm_error_monitoring_device_link_state),
						   info,
						   (GClosureNotify) g_free,
						   0);
	nm_netlink_monitor_attach (monitor);

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
			nm_log_warn (LOGD_CORE, "caught signal %d. Generating backtrace...", signo);
			nm_logging_backtrace ();
			exit (1);
			break;

		case SIGFPE:
		case SIGPIPE:
			/* let the fatal signals interrupt us */
			--in_fatal;

			nm_log_warn (LOGD_CORE, "caught signal %d, shutting down abnormally. Generating backtrace...", signo);
			nm_logging_backtrace ();
			g_main_loop_quit (main_loop);
			break;

		case SIGINT:
		case SIGTERM:
			/* let the fatal signals interrupt us */
			--in_fatal;

			nm_log_info (LOGD_CORE, "caught signal %d, shutting down normally.", signo);
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

static gboolean
write_pidfile (const char *pidfile)
{
 	char pid[16];
	int fd;
	gboolean success = FALSE;
 
	if ((fd = open (pidfile, O_CREAT|O_WRONLY|O_TRUNC, 00644)) < 0) {
		fprintf (stderr, "Opening %s failed: %s\n", pidfile, strerror (errno));
		return FALSE;
	}

 	snprintf (pid, sizeof (pid), "%d", getpid ());
	if (write (fd, pid, strlen (pid)) < 0)
		fprintf (stderr, "Writing to %s failed: %s\n", pidfile, strerror (errno));
	else
		success = TRUE;

	if (close (fd))
		fprintf (stderr, "Closing %s failed: %s\n", pidfile, strerror (errno));

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
			fprintf (stderr, "NetworkManager is already running (pid %ld)\n", pid);
			nm_running = TRUE;
		}
	}

done:
	g_free (proc_cmdline);
	g_free (contents);
	return nm_running;
}

static gboolean
parse_config_file (const char *filename,
                   char **plugins,
                   char **dhcp_client,
                   char **log_level,
                   char **log_domains,
                   GError **error)
{
	GKeyFile *config;

	config = g_key_file_new ();
	if (!config) {
		g_set_error (error, 0, 0,
		             "Not enough memory to load config file.");
		return FALSE;
	}

	g_key_file_set_list_separator (config, ',');
	if (!g_key_file_load_from_file (config, filename, G_KEY_FILE_NONE, error))
		return FALSE;

	*plugins = g_key_file_get_value (config, "main", "plugins", error);
	if (*error)
		return FALSE;

	*dhcp_client = g_key_file_get_value (config, "main", "dhcp", NULL);

	*log_level = g_key_file_get_value (config, "logging", "level", NULL);
	*log_domains = g_key_file_get_value (config, "logging", "domains", NULL);

	g_key_file_free (config);
	return TRUE;
}

static gboolean
parse_state_file (const char *filename,
                  gboolean *net_enabled,
                  gboolean *wifi_enabled,
                  gboolean *wwan_enabled,
                  GError **error)
{
	GKeyFile *state_file;
	GError *tmp_error = NULL;
	gboolean wifi, net, wwan;

	g_return_val_if_fail (net_enabled != NULL, FALSE);
	g_return_val_if_fail (wifi_enabled != NULL, FALSE);
	g_return_val_if_fail (wwan_enabled != NULL, FALSE);

	state_file = g_key_file_new ();
	if (!state_file) {
		g_set_error (error, 0, 0,
		             "Not enough memory to load state file.");
		return FALSE;
	}

	g_key_file_set_list_separator (state_file, ',');
	if (!g_key_file_load_from_file (state_file, filename, G_KEY_FILE_KEEP_COMMENTS, &tmp_error)) {
		/* This is kinda ugly; create the file and directory if it doesn't
		 * exist yet.  We can't rely on distros necessarily creating the
		 * /var/lib/NetworkManager for us since we have to ensure that
		 * users upgrading NM get this working too.
		 */
		if (   tmp_error->domain == G_FILE_ERROR
		    && tmp_error->code == G_FILE_ERROR_NOENT) {
			char *data, *dirname;
			gsize len = 0;
			gboolean ret = FALSE;

			/* try to create the directory if it doesn't exist */
			dirname = g_path_get_dirname (filename);
			errno = 0;
			if (mkdir (dirname, 0755) != 0) {
				if (errno != EEXIST) {
					g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_ACCES,
					             "Error creating state directory %s: %d", dirname, errno);
					g_free (dirname);
					return FALSE;
				}
			}
			g_free (dirname);

			/* Write out the initial state to the state file */
			g_key_file_set_boolean (state_file, "main", "NetworkingEnabled", *net_enabled);
			g_key_file_set_boolean (state_file, "main", "WirelessEnabled", *wifi_enabled);
			g_key_file_set_boolean (state_file, "main", "WWANEnabled", *wwan_enabled);

			data = g_key_file_to_data (state_file, &len, NULL);
			if (data)
				ret = g_file_set_contents (filename, data, len, error);
			g_free (data);

			return ret;
		} else {
			g_set_error_literal (error, tmp_error->domain, tmp_error->code, tmp_error->message);
			g_clear_error (&tmp_error);
		}

		/* Otherwise, file probably corrupt or inaccessible */
		return FALSE;
	}

	/* Reading state bits of NetworkManager; an error leaves the passed-in state
	 * value unchanged.
	 */
	net = g_key_file_get_boolean (state_file, "main", "NetworkingEnabled", &tmp_error);
	if (tmp_error)
		g_set_error_literal (error, tmp_error->domain, tmp_error->code, tmp_error->message);
	else
		*net_enabled = net;
	g_clear_error (&tmp_error);

	wifi = g_key_file_get_boolean (state_file, "main", "WirelessEnabled", &tmp_error);
	if (tmp_error) {
		g_clear_error (error);
		g_set_error_literal (error, tmp_error->domain, tmp_error->code, tmp_error->message);
	} else
		*wifi_enabled = wifi;
	g_clear_error (&tmp_error);

	wwan = g_key_file_get_boolean (state_file, "main", "WWANEnabled", &tmp_error);
	if (tmp_error) {
		g_clear_error (error);
		g_set_error_literal (error, tmp_error->domain, tmp_error->code, tmp_error->message);
	} else
		*wwan_enabled = wwan;
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
	char *pidfile = NULL, *state_file = NULL, *dhcp = NULL;
	char *config = NULL, *plugins = NULL, *conf_plugins = NULL;
	char *log_level = NULL, *log_domains = NULL;
	gboolean wifi_enabled = TRUE, net_enabled = TRUE, wwan_enabled = TRUE;
	gboolean success;
	NMPolicy *policy = NULL;
	NMVPNManager *vpn_manager = NULL;
	NMNamedManager *named_mgr = NULL;
	NMDBusManager *dbus_mgr = NULL;
	NMSupplicantManager *sup_mgr = NULL;
	NMDHCPManager *dhcp_mgr = NULL;
	GError *error = NULL;
	gboolean wrote_pidfile = FALSE;
	char *cfg_log_level = NULL, *cfg_log_domains = NULL;

	GOptionEntry options[] = {
		{ "no-daemon", 0, 0, G_OPTION_ARG_NONE, &become_daemon, "Don't become a daemon", NULL },
		{ "g-fatal-warnings", 0, 0, G_OPTION_ARG_NONE, &g_fatal_warnings, "Make all warnings fatal", NULL },
		{ "pid-file", 0, 0, G_OPTION_ARG_FILENAME, &pidfile, "Specify the location of a PID file", "filename" },
		{ "state-file", 0, 0, G_OPTION_ARG_FILENAME, &state_file, "State file location", "/path/to/state.file" },
		{ "config", 0, 0, G_OPTION_ARG_FILENAME, &config, "Config file location", "/path/to/config.file" },
		{ "plugins", 0, 0, G_OPTION_ARG_STRING, &plugins, "List of plugins separated by ','", "plugin1,plugin2" },
		{ "log-level", 0, 0, G_OPTION_ARG_STRING, &log_level, "Log level: one of [ERR, WARN, INFO, DEBUG]", "INFO" },
		{ "log-domains", 0, 0, G_OPTION_ARG_STRING, &log_domains,
		        "Log domains separated by ',': any combination of [NONE,HW,RKILL,ETHER,WIFI,BT,MB,DHCP4,DHCP6,PPP,WIFI_SCAN,IP4,IP6,AUTOIP4,DNS,VPN,SHARING,SUPPLICANT,USER_SET,SYS_SET,SUSPEND,CORE,DEVICE,OLPC]",
		        "HW,RFKILL,WIFI" },
		{NULL}
	};

	if (getuid () != 0) {
		fprintf (stderr, "You must be root to run NetworkManager!\n");
		exit (1);
	}

	if (!g_module_supported ()) {
		fprintf (stderr, "GModules are not supported on your platform!\n");
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

	/* Parse the config file */
	if (config) {
		if (!parse_config_file (config, &conf_plugins, &dhcp, &cfg_log_level, &cfg_log_domains, &error)) {
			fprintf (stderr, "Config file %s invalid: (%d) %s\n",
			         config,
			         error ? error->code : -1,
			         (error && error->message) ? error->message : "unknown");
			exit (1);
		}
	} else {
		gboolean parsed = FALSE;

		/* Even though we prefer NetworkManager.conf, we need to check the
		 * old nm-system-settings.conf first to preserve compat with older
		 * setups.  In package managed systems dropping a NetworkManager.conf
		 * onto the system would make NM use it instead of nm-system-settings.conf,
		 * changing behavior during an upgrade.  We don't want that.
		 */

		/* Try deprecated nm-system-settings.conf first */
		if (g_file_test (NM_OLD_SYSTEM_CONF_FILE, G_FILE_TEST_EXISTS)) {
			config = g_strdup (NM_OLD_SYSTEM_CONF_FILE);
			parsed = parse_config_file (config, &conf_plugins, &dhcp, &cfg_log_level, &cfg_log_domains, &error);
			if (!parsed) {
				fprintf (stderr, "Default config file %s invalid: (%d) %s\n",
				         config,
				         error ? error->code : -1,
				         (error && error->message) ? error->message : "unknown");
				g_free (config);
				config = NULL;
				g_clear_error (&error);
			}
		}

		/* Try the preferred NetworkManager.conf last */
		if (!parsed && g_file_test (NM_DEFAULT_SYSTEM_CONF_FILE, G_FILE_TEST_EXISTS)) {
			config = g_strdup (NM_DEFAULT_SYSTEM_CONF_FILE);
			parsed = parse_config_file (config, &conf_plugins, &dhcp, &cfg_log_level, &cfg_log_domains, &error);
			if (!parsed) {
				fprintf (stderr, "Default config file %s invalid: (%d) %s\n",
				         config,
				         error ? error->code : -1,
				         (error && error->message) ? error->message : "unknown");
				g_free (config);
				config = NULL;
				g_clear_error (&error);
			}
		}
	}
	/* Logging setup */
	if (!nm_logging_setup (log_level ? log_level : cfg_log_level,
	                       log_domains ? log_domains : cfg_log_domains,
	                       &error)) {
		fprintf (stderr,
		         _("%s.  Please use --help to see a list of valid options.\n"),
		         error->message);
		exit (1);
	}

	/* Plugins specified with '--plugins' override those of config file */
	plugins = plugins ? plugins : g_strdup (conf_plugins);
	g_free (conf_plugins);

	/* Parse the state file */
	if (!parse_state_file (state_file, &net_enabled, &wifi_enabled, &wwan_enabled, &error)) {
		fprintf (stderr, "State file %s parsing failed: (%d) %s\n",
		         state_file,
		         error ? error->code : -1,
		         (error && error->message) ? error->message : "unknown");
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
			fprintf (stderr, "Could not daemonize: %s [error %u]\n",
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
	if (!g_thread_supported ())
		g_thread_init (NULL);
	dbus_g_thread_init ();

	setup_signals ();

	nm_logging_start (become_daemon);

	nm_log_info (LOGD_CORE, "NetworkManager (version " NM_DIST_VERSION ") is starting...");
	success = FALSE;

	if (config)
		nm_log_info (LOGD_CORE, "Read config file %s", config);

	main_loop = g_main_loop_new (NULL, FALSE);

	/* Create watch functions that monitor cards for link status. */
	if (!nm_monitor_setup (&error)) {
		nm_log_err (LOGD_CORE, "failed to start monitoring devices: %s.",
		            error && error->message ? error->message : "(unknown)");
		goto done;
	}

	/* Initialize our DBus service & connection */
	dbus_mgr = nm_dbus_manager_get ();

	vpn_manager = nm_vpn_manager_get ();
	if (!vpn_manager) {
		nm_log_err (LOGD_CORE, "failed to start the VPN manager.");
		goto done;
	}

	named_mgr = nm_named_manager_get ();
	if (!named_mgr) {
		nm_log_err (LOGD_CORE, "failed to start the named manager.");
		goto done;
	}

	manager = nm_manager_get (config,
	                          plugins,
	                          state_file,
	                          net_enabled,
	                          wifi_enabled,
	                          wwan_enabled,
	                          &error);
	if (manager == NULL) {
		nm_log_err (LOGD_CORE, "failed to initialize the network manager: %s",
		          error && error->message ? error->message : "(unknown)");
		goto done;
	}

	policy = nm_policy_new (manager, vpn_manager);
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
	dhcp_mgr = nm_dhcp_manager_new (dhcp, &error);
	if (!dhcp_mgr) {
		nm_log_err (LOGD_CORE, "failed to start the DHCP manager: %s.", error->message);
		goto done;
	}

	nm_dhcp_manager_set_hostname_provider (dhcp_mgr, NM_HOSTNAME_PROVIDER (manager));

	/* Start our DBus service */
	if (!nm_dbus_manager_start_service (dbus_mgr)) {
		nm_log_err (LOGD_CORE, "failed to start the dbus service.");
		goto done;
	}

	nm_manager_start (manager);

	/* Bring up the loopback interface. */
	nm_system_enable_loopback ();

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

	if (vpn_manager)
		g_object_unref (vpn_manager);

	if (named_mgr)
		g_object_unref (named_mgr);

	if (dhcp_mgr)
		g_object_unref (dhcp_mgr);

	if (sup_mgr)
		g_object_unref (sup_mgr);

	if (dbus_mgr)
		g_object_unref (dbus_mgr);

	nm_logging_shutdown ();

	if (pidfile && wrote_pidfile)
		unlink (pidfile);

	/* Free options */
	g_free (pidfile);
	g_free (state_file);
	g_free (config);
	g_free (plugins);
	g_free (dhcp);
	g_free (log_level);
	g_free (log_domains);
	g_free (cfg_log_level);
	g_free (cfg_log_domains);

	nm_log_info (LOGD_CORE, "exiting (%s)", success ? "success" : "error");
	exit (success ? 0 : 1);
}
