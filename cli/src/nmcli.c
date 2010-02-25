/* nmcli - command-line tool to control NetworkManager
 *
 * Jiri Klimes <jklimes@redhat.com>
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
 * (C) Copyright 2010 Red Hat, Inc.
 */

/* Generated configuration file */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <locale.h>

#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <nm-client.h>
#include <nm-setting-connection.h>
#include <nm-remote-settings.h>
#include <nm-remote-settings-system.h>
#include <nm-settings-interface.h>
#include <nm-settings-connection-interface.h>

#include "nmcli.h"
#include "utils.h"
#include "connections.h"
#include "devices.h"
#include "network-manager.h"

#define NMCLI_VERSION "0.1"


typedef struct {
	NmCli *nmc;
	int argc;
	char **argv;
} ArgsInfo;

/* --- Global variables --- */
GMainLoop *loop = NULL;


static void
usage (const char *prog_name)
{
	fprintf (stderr,
	         _("Usage: %s [OPTIONS] OBJECT { COMMAND | help }\n\n"
	         "OPTIONS\n"
	         "  -t[erse]    terse output\n"
	         "  -p[retty]   pretty output\n"
	         "  -v[ersion]  show program version\n"
	         "  -h[elp]     print this help\n\n"
	         "OBJECT\n"
	         "  nm          NetworkManager status\n"
	         "  con         NetworkManager connections\n"
	         "  dev         devices managed by NetworkManager\n\n"),
	          prog_name);
}

static NMCResultCode 
do_help (NmCli *nmc, int argc, char **argv)
{
	usage ("nmcli");
	return NMC_RESULT_SUCCESS;
}

static const struct cmd {
	const char *cmd;
	NMCResultCode (*func) (NmCli *nmc, int argc, char **argv);
} nmcli_cmds[] = {
	{ "nm",         do_network_manager },
	{ "con",        do_connections },
	{ "dev",        do_devices },
	{ "help",       do_help },
	{ 0 }
};

static NMCResultCode
do_cmd (NmCli *nmc, const char *argv0, int argc, char **argv)
{
	const struct cmd *c;

	for (c = nmcli_cmds; c->cmd; ++c) {
		if (matches (argv0, c->cmd) == 0)
			return c->func (nmc, argc-1, argv+1);
	}

	g_string_printf (nmc->return_text, _("Object '%s' is unknown, try 'nmcli help'."), argv0);
	nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
	return nmc->return_value;
}

static NMCResultCode
parse_command_line (NmCli *nmc, int argc, char **argv)
{
	char *base;

	base = strrchr (argv[0], '/');
	if (base == NULL)
		base = argv[0];
	else
		base++;

	/* parse options */
	while (argc > 1) {
		char *opt = argv[1];
		/* '--' ends options */
		if (strcmp (opt, "--") == 0) {
			argc--; argv++;
			break;
		}
		if (opt[0] != '-')
			break;
		if (opt[1] == '-')
			opt++;
		if (matches (opt, "-terse") == 0) {
			nmc->print_output = NMC_PRINT_TERSE;
		} else if (matches (opt, "-pretty") == 0) {
			nmc->print_output = NMC_PRINT_PRETTY;
		} else if (matches (opt, "-version") == 0) {
			printf (_("nmcli tool, version %s\n"), NMCLI_VERSION);
			return NMC_RESULT_SUCCESS;
		} else if (matches (opt, "-help") == 0) {
			usage (base);
			return NMC_RESULT_SUCCESS;
		} else {
			g_string_printf (nmc->return_text, _("Option '%s' is unknown, try 'nmcli -help'."), opt);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			return nmc->return_value;
		}
		argc--;
		argv++;
	}

	if (argc > 1)
		return do_cmd (nmc, argv[1], argc-1, argv+1);

	usage (base);
	return nmc->return_value;
}

static void
signal_handler (int signo)
{
	if (signo == SIGINT || signo == SIGTERM) {
		g_message (_("Caught signal %d, shutting down..."), signo);
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

static NMClient *
nmc_get_client (NmCli *nmc)
{
	if (!nmc->client) {
		nmc->client = nm_client_new ();
		if (!nmc->client) {
			g_string_printf (nmc->return_text, _("Error: Could not connect to NetworkManager."));
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		}
	}

	return nmc->client;
}

/* Initialize NmCli structure - set default values */
static void
nmc_init (NmCli *nmc)
{
	nmc->client = NULL;
	nmc->get_client = &nmc_get_client;

	nmc->return_value = NMC_RESULT_SUCCESS;
	nmc->return_text = g_string_new (_("Success"));

	nmc->timeout = 10;

	nmc->system_settings = NULL;
	nmc->user_settings = NULL;

	nmc->system_settings_running = FALSE;
	nmc->user_settings_running = FALSE;

	nmc->system_connections = NULL;
	nmc->user_connections = NULL;

	nmc->should_wait = FALSE;
	nmc->print_output = NMC_PRINT_NORMAL;
}

static void
nmc_cleanup (NmCli *nmc)
{
	if (nmc->client) g_object_unref (nmc->client);

	g_string_free (nmc->return_text, TRUE);

	if (nmc->system_settings) g_object_unref (nmc->system_settings);
	if (nmc->user_settings) g_object_unref (nmc->user_settings);

	g_slist_free (nmc->system_connections);
	g_slist_free (nmc->user_connections);
}

static gboolean
start (gpointer data)
{
	ArgsInfo *info = (ArgsInfo *) data;
	info->nmc->return_value = parse_command_line (info->nmc, info->argc, info->argv);

	if (!info->nmc->should_wait)
		g_main_loop_quit (loop);

	return FALSE;
}


int
main (int argc, char *argv[])
{
	NmCli nmc;
	ArgsInfo args_info = { &nmc, argc, argv };

	/* Set locale to use environment variables */
	setlocale (LC_ALL, "");

#ifdef GETTEXT_PACKAGE
	/* Set i18n stuff */
	bindtextdomain (GETTEXT_PACKAGE, NMCLI_LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);
#endif

	g_type_init ();

	nmc_init (&nmc);
	g_idle_add (start, &args_info);

	loop = g_main_loop_new (NULL, FALSE);  /* create main loop */
	setup_signals ();                      /* setup UNIX signals */
	g_main_loop_run (loop);                /* run main loop */

	/* Print result descripting text */
	if (nmc.return_value != NMC_RESULT_SUCCESS) {
		fprintf (stderr, "%s\n", nmc.return_text->str);
	}

	g_main_loop_unref (loop);
	nmc_cleanup (&nmc);

	return nmc.return_value;
}
