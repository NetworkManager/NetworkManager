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
 * Copyright 2010 - 2015 Red Hat, Inc.
 */

/* Generated configuration file */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <termios.h>
#include <unistd.h>
#include <locale.h>
#include <readline/readline.h>
#include <readline/history.h>

#include <glib/gi18n.h>

#include "nm-glib.h"
#include "polkit-agent.h"
#include "nmcli.h"
#include "utils.h"
#include "common.h"
#include "connections.h"
#include "devices.h"
#include "general.h"
#include "agent.h"

#if defined(NM_DIST_VERSION)
# define NMCLI_VERSION NM_DIST_VERSION
#else
# define NMCLI_VERSION VERSION
#endif

/* Global NmCli object */
// FIXME: Currently, we pass NmCli over in most APIs, but we might refactor
// that and use the global variable directly instead.
NmCli nm_cli;

typedef struct {
	NmCli *nmc;
	int argc;
	char **argv;
} ArgsInfo;

/* --- Global variables --- */
GMainLoop *loop = NULL;
static sigset_t signal_set;
struct termios termios_orig;


/* Get an error quark for use with GError */
GQuark
nmcli_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("nmcli-error-quark");

	return error_quark;
}

static void
usage (const char *prog_name)
{
	g_printerr (_("Usage: %s [OPTIONS] OBJECT { COMMAND | help }\n"
	              "\n"
	              "OPTIONS\n"
	              "  -t[erse]                                   terse output\n"
	              "  -p[retty]                                  pretty output\n"
	              "  -m[ode] tabular|multiline                  output mode\n"
	              "  -c[olors] auto|yes|no                      whether to use colors in output\n"
	              "  -f[ields] <field1,field2,...>|all|common   specify fields to output\n"
	              "  -e[scape] yes|no                           escape columns separators in values\n"
	              "  -n[ocheck]                                 don't check nmcli and NetworkManager versions\n"
	              "  -a[sk]                                     ask for missing parameters\n"
	              "  -w[ait] <seconds>                          set timeout waiting for finishing operations\n"
	              "  -v[ersion]                                 show program version\n"
	              "  -h[elp]                                    print this help\n"
	              "\n"
	              "OBJECT\n"
	              "  g[eneral]       NetworkManager's general status and operations\n"
	              "  n[etworking]    overall networking control\n"
	              "  r[adio]         NetworkManager radio switches\n"
	              "  c[onnection]    NetworkManager's connections\n"
	              "  d[evice]        devices managed by NetworkManager\n"
	              "  a[gent]         NetworkManager secret agent or polkit agent\n"
	              "\n"),
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
	{ "general",    do_general },
	{ "networking", do_networking },
	{ "radio",      do_radio },
	{ "connection", do_connections },
	{ "device",     do_devices },
	{ "agent",      do_agent },
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

	g_string_printf (nmc->return_text, _("Error: Object '%s' is unknown, try 'nmcli help'."), argv0);
	nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
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
			if (nmc->print_output == NMC_PRINT_TERSE) {
				g_string_printf (nmc->return_text, _("Error: Option '--terse' is specified the second time."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			else if (nmc->print_output == NMC_PRINT_PRETTY) {
				g_string_printf (nmc->return_text, _("Error: Option '--terse' is mutually exclusive with '--pretty'."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			else
				nmc->print_output = NMC_PRINT_TERSE;
		} else if (matches (opt, "-pretty") == 0) {
			if (nmc->print_output == NMC_PRINT_PRETTY) {
				g_string_printf (nmc->return_text, _("Error: Option '--pretty' is specified the second time."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			else if (nmc->print_output == NMC_PRINT_TERSE) {
				g_string_printf (nmc->return_text, _("Error: Option '--pretty' is mutually exclusive with '--terse'."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			else
				nmc->print_output = NMC_PRINT_PRETTY;
		} else if (matches (opt, "-mode") == 0) {
			nmc->mode_specified = TRUE;
			next_arg (&argc, &argv);
			if (argc <= 1) {
		 		g_string_printf (nmc->return_text, _("Error: missing argument for '%s' option."), opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			if (matches (argv[1], "tabular") == 0)
				nmc->multiline_output = FALSE;
			else if (matches (argv[1], "multiline") == 0)
				nmc->multiline_output = TRUE;
			else {
		 		g_string_printf (nmc->return_text, _("Error: '%s' is not valid argument for '%s' option."), argv[1], opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
		} else if (matches (opt, "-colors") == 0) {
			next_arg (&argc, &argv);
			if (argc <= 1) {
		 		g_string_printf (nmc->return_text, _("Error: missing argument for '%s' option."), opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			if (matches (argv[1], "auto") == 0)
				nmc->use_colors = NMC_USE_COLOR_AUTO;
			else if (matches (argv[1], "yes") == 0)
				nmc->use_colors = NMC_USE_COLOR_YES;
			else if (matches (argv[1], "no") == 0)
				nmc->use_colors = NMC_USE_COLOR_NO;
			else {
		 		g_string_printf (nmc->return_text, _("Error: '%s' is not valid argument for '%s' option."), argv[1], opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
		} else if (matches (opt, "-escape") == 0) {
			next_arg (&argc, &argv);
			if (argc <= 1) {
		 		g_string_printf (nmc->return_text, _("Error: missing argument for '%s' option."), opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			if (matches (argv[1], "yes") == 0)
				nmc->escape_values = TRUE;
			else if (matches (argv[1], "no") == 0)
				nmc->escape_values = FALSE;
			else {
		 		g_string_printf (nmc->return_text, _("Error: '%s' is not valid argument for '%s' option."), argv[1], opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
		} else if (matches (opt, "-fields") == 0) {
			next_arg (&argc, &argv);
			if (argc <= 1) {
		 		g_string_printf (nmc->return_text, _("Error: fields for '%s' options are missing."), opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			nmc->required_fields = g_strdup (argv[1]);
		} else if (matches (opt, "-nocheck") == 0) {
			nmc->nocheck_ver = TRUE;
		} else if (matches (opt, "-ask") == 0) {
			nmc->ask = TRUE;
		} else if (matches (opt, "-wait") == 0) {
			unsigned long timeout;
			next_arg (&argc, &argv);
			if (argc <= 1) {
		 		g_string_printf (nmc->return_text, _("Error: missing argument for '%s' option."), opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			if (!nmc_string_to_uint (argv[1], TRUE, 0, G_MAXINT, &timeout)) {
		 		g_string_printf (nmc->return_text, _("Error: '%s' is not a valid timeout for '%s' option."),
				                 argv[1], opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			nmc->timeout = (int) timeout;
		} else if (matches (opt, "-version") == 0) {
			g_print (_("nmcli tool, version %s\n"), NMCLI_VERSION);
			return NMC_RESULT_SUCCESS;
		} else if (matches (opt, "-help") == 0) {
			usage (base);
			return NMC_RESULT_SUCCESS;
		} else {
			g_string_printf (nmc->return_text, _("Error: Option '%s' is unknown, try 'nmcli -help'."), opt);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			return nmc->return_value;
		}
		argc--;
		argv++;
	}

	if (argc > 1) {
		/* Now run the requested command */
		return do_cmd (nmc, argv[1], argc-1, argv+1);
	}

	usage (base);
	return nmc->return_value;
}

static gboolean nmcli_sigint = FALSE;
static pthread_mutex_t sigint_mutex = PTHREAD_MUTEX_INITIALIZER;
static gboolean nmcli_sigquit_internal = FALSE;

gboolean
nmc_seen_sigint (void)
{
	gboolean sigint;

	pthread_mutex_lock (&sigint_mutex);
	sigint = nmcli_sigint;
	pthread_mutex_unlock (&sigint_mutex);
	return sigint;
}

void
nmc_clear_sigint (void)
{
	pthread_mutex_lock (&sigint_mutex);
	nmcli_sigint = FALSE;
	pthread_mutex_unlock (&sigint_mutex);
}

void
nmc_set_sigquit_internal (void)
{
	nmcli_sigquit_internal = TRUE;
}

static int
event_hook_for_readline (void)
{
	/* Make readline() exit on SIGINT */
	if (nmc_seen_sigint ()) {
		rl_echo_signal_char (SIGINT);
		rl_stuff_char ('\n');
	}
	return 0;
}

void *signal_handling_thread (void *arg);
/*
 * Thread function waiting for signals and processing them.
 * Wait for signals in signal set. The semantics of sigwait() require that all
 * threads (including the thread calling sigwait()) have the signal masked, for
 * reliable operation. Otherwise, a signal that arrives while this thread is
 * not blocked in sigwait() might be delivered to another thread.
 */
void *
signal_handling_thread (void *arg) {
	int signo;

	while (1) {
		sigwait (&signal_set, &signo);

		switch (signo) {
		case SIGINT:
			if (nmc_get_in_readline ()) {
				/* Don't quit when in readline, only signal we received SIGINT */
				pthread_mutex_lock (&sigint_mutex);
				nmcli_sigint = TRUE;
				pthread_mutex_unlock (&sigint_mutex);
			} else {
				/* We can quit nmcli */
				tcsetattr (STDIN_FILENO, TCSADRAIN, &termios_orig);
				nmc_cleanup_readline ();
				g_print (_("\nError: nmcli terminated by signal %s (%d)\n"),
				         strsignal (signo), signo);
				exit (1);
			}
			break;
		case SIGQUIT:
		case SIGTERM:
			tcsetattr (STDIN_FILENO, TCSADRAIN, &termios_orig);
			nmc_cleanup_readline ();
			if (!nmcli_sigquit_internal)
				g_print (_("\nError: nmcli terminated by signal %s (%d)\n"),
				         strsignal (signo), signo);
			exit (1);
			break;
		default:
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
	sigaddset (&signal_set, SIGINT);
	sigaddset (&signal_set, SIGQUIT);
	sigaddset (&signal_set, SIGTERM);

	/* Block all signals of interest. */
	status = pthread_sigmask (SIG_BLOCK, &signal_set, NULL);
	if (status != 0) {
		g_printerr (_("Failed to set signal mask: %d\n"), status);
		return FALSE;
	}

	/* Create the signal handling thread. */
	status = pthread_create (&signal_thread_id, NULL, signal_handling_thread, NULL);
	if (status != 0) {
		g_printerr (_("Failed to create signal handling thread: %d\n"), status);
		return FALSE;
	}

	return TRUE;
}

static void
nmc_convert_strv_to_string (const GValue *src_value, GValue *dest_value)
{
	char **strings;

	strings = g_value_get_boxed (src_value);
	if (strings)
		g_value_take_string (dest_value, g_strjoinv (",", strings));
	else
		g_value_set_string (dest_value, "");
}

static void
nmc_convert_string_hash_to_string (const GValue *src_value, GValue *dest_value)
{
	GHashTable *hash;
	GHashTableIter iter;
	const char *key, *value;
	GString *string;

	hash = (GHashTable *) g_value_get_boxed (src_value);

	string = g_string_new (NULL);
	if (hash) {
		g_hash_table_iter_init (&iter, hash);
		while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &value)) {
			if (string->len)
				g_string_append_c (string, ',');
			g_string_append_printf (string, "%s=%s", key, value);
		}
	}

	g_value_take_string (dest_value, g_string_free (string, FALSE));
}

static void
nmc_convert_bytes_to_string (const GValue *src_value, GValue *dest_value)
{
	GBytes *bytes;
	const guint8 *array;
	gsize length;
	GString *printable;
	guint i = 0;

	bytes = g_value_get_boxed (src_value);

	printable = g_string_new ("[");

	if (bytes) {
		array = g_bytes_get_data (bytes, &length);
		while (i < MIN (length, 35)) {
			if (i > 0)
				g_string_append_c (printable, ' ');
			g_string_append_printf (printable, "0x%02X", array[i++]);
		}
		if (i < length)
			g_string_append (printable, " ... ");
	}
	g_string_append_c (printable, ']');

	g_value_take_string (dest_value, g_string_free (printable, FALSE));
}

static void
nmc_value_transforms_register (void)
{
	g_value_register_transform_func (G_TYPE_STRV,
	                                 G_TYPE_STRING,
	                                 nmc_convert_strv_to_string);

	/* This depends on the fact that all of the hash-table-valued properties
	 * in libnm-core are string->string.
	 */
	g_value_register_transform_func (G_TYPE_HASH_TABLE,
	                                 G_TYPE_STRING,
	                                 nmc_convert_string_hash_to_string);

	g_value_register_transform_func (G_TYPE_BYTES,
	                                 G_TYPE_STRING,
	                                 nmc_convert_bytes_to_string);
}

static NMClient *
nmc_get_client (NmCli *nmc)
{
	GError *error = NULL;

	if (!nmc->client) {
		nmc->client = nm_client_new (NULL, &error);
		if (!nmc->client) {
			g_critical (_("Error: Could not create NMClient object: %s."), error->message);
			g_clear_error (&error);
			exit (NMC_RESULT_ERROR_UNKNOWN);
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

	nmc->timeout = -1;

	nmc->connections = NULL;

	nmc->secret_agent = NULL;
	nmc->pwds_hash = NULL;
	nmc->pk_listener = NULL;

	nmc->should_wait = FALSE;
	nmc->nowait_flag = TRUE;
	nmc->print_output = NMC_PRINT_NORMAL;
	nmc->multiline_output = FALSE;
	nmc->mode_specified = FALSE;
	nmc->escape_values = TRUE;
	nmc->required_fields = NULL;
	nmc->output_data = g_ptr_array_new_full (20, g_free);
	memset (&nmc->print_fields, '\0', sizeof (NmcPrintFields));
	nmc->nocheck_ver = FALSE;
	nmc->ask = FALSE;
	nmc->use_colors = NMC_USE_COLOR_AUTO;
	nmc->in_editor = FALSE;
	nmc->editor_status_line = FALSE;
	nmc->editor_save_confirmation = TRUE;
	nmc->editor_show_secrets = FALSE;
	nmc->editor_prompt_color = NMC_TERM_COLOR_NORMAL;
}

static void
nmc_cleanup (NmCli *nmc)
{
	if (nmc->client) g_object_unref (nmc->client);

	g_string_free (nmc->return_text, TRUE);

	if (nmc->secret_agent) {
		/* Destroy secret agent if we have one. */
		nm_secret_agent_old_unregister (nmc->secret_agent, NULL, NULL);
		g_object_unref (nmc->secret_agent);
	}
	if (nmc->pwds_hash)
		g_hash_table_destroy (nmc->pwds_hash);

	g_free (nmc->required_fields);
	nmc_empty_output_fields (nmc);
	g_ptr_array_unref (nmc->output_data);

	nmc_polkit_agent_fini (nmc);
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
	ArgsInfo args_info = { &nm_cli, argc, argv };

	/* Set up unix signal handling */
	if (!setup_signals ())
		exit (NMC_RESULT_ERROR_UNKNOWN);

	/* Set locale to use environment variables */
	setlocale (LC_ALL, "");

#ifdef GETTEXT_PACKAGE
	/* Set i18n stuff */
	bindtextdomain (GETTEXT_PACKAGE, NMCLI_LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);
#endif

	nm_g_type_init ();

	/* Save terminal settings */
	tcgetattr (STDIN_FILENO, &termios_orig);

	/* readline init */
	rl_event_hook = event_hook_for_readline;
	/* Set 0.01s timeout to mitigate slowness in readline when a broken version is used.
	 * See https://bugzilla.redhat.com/show_bug.cgi?id=1109946
	 */
	rl_set_keyboard_input_timeout (10000);

	nmc_value_transforms_register ();

	nmc_init (&nm_cli);
	g_idle_add (start, &args_info);

	loop = g_main_loop_new (NULL, FALSE);  /* create main loop */
	g_main_loop_run (loop);                /* run main loop */

	/* Print result descripting text */
	if (nm_cli.return_value != NMC_RESULT_SUCCESS) {
		g_printerr ("%s\n", nm_cli.return_text->str);
	}

	g_main_loop_unref (loop);
	nmc_cleanup (&nm_cli);

	return nm_cli.return_value;
}
