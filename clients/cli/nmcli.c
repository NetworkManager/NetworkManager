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
 * Copyright 2010 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nmcli.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <locale.h>
#include <glib-unix.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "nm-client-utils.h"

#include "nm-utils/nm-hash-utils.h"

#include "polkit-agent.h"
#include "utils.h"
#include "common.h"
#include "connections.h"
#include "devices.h"
#include "general.h"
#include "agent.h"
#include "settings.h"

#if defined(NM_DIST_VERSION)
# define NMCLI_VERSION NM_DIST_VERSION
#else
# define NMCLI_VERSION VERSION
#endif

/* Global NmCli object */
NmCli nm_cli;

/*****************************************************************************/

typedef struct {
	NmCli *nmc;
	int argc;
	char **argv;
} ArgsInfo;

/* --- Global variables --- */
GMainLoop *loop = NULL;
struct termios termios_orig;

NM_CACHED_QUARK_FCN ("nmcli-error-quark", nmcli_error_quark)

static void
complete_field_setting (GHashTable *h, NMMetaSettingType setting_type)
{
	const NMMetaSettingInfoEditor *setting_info = &nm_meta_setting_infos_editor[setting_type];
	guint i;

	for (i = 0; i < setting_info->properties_num; i++) {
		g_hash_table_add (h, g_strdup_printf ("%s.%s",
		                                      setting_info->general->setting_name,
		                                      setting_info->properties[i]->property_name));
	}
}

static void
complete_field (GHashTable *h, const NmcMetaGenericInfo *const*field)
{
	int i;

	for (i = 0; field[i]; i++)
		g_hash_table_add (h, g_strdup (field[i]->name));
}

static void
complete_one (gpointer key, gpointer value, gpointer user_data)
{
	const char **option_with_value = user_data;
	const char *option = option_with_value[0];
	const char *prefix = option_with_value[1];
	const char *name = key;
	const char *last;

	last = strrchr (prefix, ',');
	if (last)
		last++;
	else
		last = prefix;

	if ((!*last && !strchr (name, '.')) || matches (last, name)) {
		if (option != prefix) {
			/* value prefix was not a standalone argument,
			 * it was part of --option=<value> argument.
			 * Repeat the part leading to "=". */
			g_print ("%s=", option);
		}
		g_print ("%.*s%s%s\n", (int)(last-prefix), prefix, name,
		                       strcmp (last, name) == 0 ? "," : "");
	}
}

static void
complete_fields (const char *option, const char *prefix)
{
	guint i;
	GHashTable *h;
	const char *option_with_value[2] = { option, prefix };

	h = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, NULL);

	complete_field (h, metagen_ip4_config);
	complete_field (h, nmc_fields_dhcp4_config);
	complete_field (h, nmc_fields_ip6_config);
	complete_field (h, nmc_fields_dhcp6_config);
	complete_field (h, nmc_fields_con_show);
	complete_field (h, nmc_fields_con_active_details_general);
	complete_field (h, nmc_fields_con_active_details_vpn);
	complete_field (h, nmc_fields_con_active_details_groups);
	complete_field (h, nmc_fields_dev_status);
	complete_field (h, nmc_fields_dev_show_general);
	complete_field (h, nmc_fields_dev_show_connections);
	complete_field (h, nmc_fields_dev_show_cap);
	complete_field (h, nmc_fields_dev_show_wired_prop);
	complete_field (h, nmc_fields_dev_show_wifi_prop);
	complete_field (h, nmc_fields_dev_show_wimax_prop);
	complete_field (h, nmc_fields_dev_wifi_list);
	complete_field (h, nmc_fields_dev_wimax_list);
	complete_field (h, nmc_fields_dev_show_master_prop);
	complete_field (h, nmc_fields_dev_show_team_prop);
	complete_field (h, nmc_fields_dev_show_vlan_prop);
	complete_field (h, nmc_fields_dev_show_bluetooth);
	complete_field (h, nmc_fields_dev_show_sections);
	complete_field (h, nmc_fields_dev_lldp_list);

	for (i = 0; i < _NM_META_SETTING_TYPE_NUM; i++)
		complete_field_setting (h, i);

	g_hash_table_foreach (h, complete_one, (gpointer) &option_with_value[0]);
	g_hash_table_destroy (h);
}

static void
complete_option_with_value (const char *option, const char *prefix, ...)
{
	va_list args;
	const char *candidate;

	va_start (args, prefix);
	while ((candidate = va_arg (args, const char *))) {
		if (!*prefix || matches (prefix, candidate)) {
			if (option != prefix) {
				/* value prefix was not a standalone argument,
				 * it was part of --option=<value> argument.
				 * Repeat the part leading to "=". */
				g_print ("%s=", option);
			}
			g_print ("%s\n", candidate);
		}
	}
	va_end (args);
}

static void
usage (void)
{
	g_printerr (_("Usage: nmcli [OPTIONS] OBJECT { COMMAND | help }\n"
	              "\n"
	              "OPTIONS\n"
	              "  -t[erse]                                       terse output\n"
	              "  -p[retty]                                      pretty output\n"
	              "  -m[ode] tabular|multiline                      output mode\n"
	              "  -c[olors] auto|yes|no                          whether to use colors in output\n"
	              "  -f[ields] <field1,field2,...>|all|common       specify fields to output\n"
	              "  -g[et-values] <field1,field2,...>|all|common   shortcut for -m tabular -t -f\n"
	              "  -e[scape] yes|no                               escape columns separators in values\n"
	              "  -a[sk]                                         ask for missing parameters\n"
	              "  -s[how-secrets]                                allow displaying passwords\n"
	              "  -w[ait] <seconds>                              set timeout waiting for finishing operations\n"
	              "  -v[ersion]                                     show program version\n"
	              "  -h[elp]                                        print this help\n"
	              "\n"
	              "OBJECT\n"
	              "  g[eneral]       NetworkManager's general status and operations\n"
	              "  n[etworking]    overall networking control\n"
	              "  r[adio]         NetworkManager radio switches\n"
	              "  c[onnection]    NetworkManager's connections\n"
	              "  d[evice]        devices managed by NetworkManager\n"
	              "  a[gent]         NetworkManager secret agent or polkit agent\n"
	              "  m[onitor]       monitor NetworkManager changes\n"
	              "\n"));
}

static const NMCCommand nmcli_cmds[] = {
	{ "general",     do_general,      NULL,   FALSE,  FALSE },
	{ "monitor",     do_monitor,      NULL,   TRUE,   FALSE },
	{ "networking",  do_networking,   NULL,   FALSE,  FALSE },
	{ "radio",       do_radio,        NULL,   FALSE,  FALSE },
	{ "connection",  do_connections,  NULL,   FALSE,  FALSE },
	{ "device",      do_devices,      NULL,   FALSE,  FALSE },
	{ "agent",       do_agent,        NULL,   FALSE,  FALSE },
	{ NULL,          do_overview,     usage,  TRUE,   TRUE },
};

static gboolean
matches_arg (NmCli *nmc, int *argc, char ***argv, const char *pattern, char **arg)
{
	char *opt = *argv[0];

	if (nmc->return_value != NMC_RESULT_SUCCESS) {
		/* Don't process further matches if there has been an error. */
		return FALSE;
	}

	if (opt[1] == '-') {
		/* We know one '-' was already seen by the caller.
		 * Skip it if there's a second one*/
		opt++;
	}

	if (arg) {
		/* If there's a "=" separator, replace it with NUL so that matches()
		 * works and consider the part after it to be the arguemnt's value. */
		*arg = strchr (opt, '=');
		if (*arg) {
			**arg = '\0';
			(*arg)++;
		}
	}

	if (!matches (opt, pattern)) {
		if (arg && *arg) {
			/* Back off the replacement of "=". */
			(*arg)--;
			**arg = '=';
		}
		return FALSE;
	}

	if (arg && !*arg) {
		/* We need a value, but the option didn't contain a "=<value>" part.
		 * Proceed to the next argument. */
		(*argc)--;
		(*argv)++;
		if (!*argc) {
			g_string_printf (nmc->return_text, _("Error: missing argument for '%s' option."), opt);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			return FALSE;
		}
		*arg = *argv[0];
	}

	return TRUE;
}

static gboolean
process_command_line (NmCli *nmc, int argc, char **argv)
{
	char *base;

	base = strrchr (argv[0], '/');
	if (base == NULL)
		base = argv[0];
	else
		base++;
	if (argc > 1 && nm_streq (argv[1], "--complete-args")) {
		nmc->complete = TRUE;
		argv[1] = argv[0];
		next_arg (nmc, &argc, &argv, NULL);
	}
	next_arg (nmc, &argc, &argv, NULL);

	/* parse options */
	while (argc) {
		char *value;

		if (argv[0][0] != '-')
			break;

		if (argc == 1 && nmc->complete) {
			nmc_complete_strings (argv[0], "--terse", "--pretty", "--mode", "--colors", "--escape",
			                           "--fields", "--nocheck", "--get-values",
			                            "--wait", "--version", "--help", NULL);
		}

		if (argv[0][1] == '-' && argv[0][2] == '\0') {
			/* '--' ends options */
			next_arg (nmc, &argc, &argv, NULL);
			break;
		}

		if (matches_arg (nmc, &argc, &argv, "-terse", NULL)) {
			if (nmc->nmc_config.print_output == NMC_PRINT_TERSE) {
				g_string_printf (nmc->return_text, _("Error: Option '--terse' is specified the second time."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
			else if (nmc->nmc_config.print_output == NMC_PRINT_PRETTY) {
				g_string_printf (nmc->return_text, _("Error: Option '--terse' is mutually exclusive with '--pretty'."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
			else
				nmc->nmc_config_mutable.print_output = NMC_PRINT_TERSE;
		} else if (matches_arg (nmc, &argc, &argv, "-pretty", NULL)) {
			if (nmc->nmc_config.print_output == NMC_PRINT_PRETTY) {
				g_string_printf (nmc->return_text, _("Error: Option '--pretty' is specified the second time."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
			else if (nmc->nmc_config.print_output == NMC_PRINT_TERSE) {
				g_string_printf (nmc->return_text, _("Error: Option '--pretty' is mutually exclusive with '--terse'."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
			else
				nmc->nmc_config_mutable.print_output = NMC_PRINT_PRETTY;
		} else if (matches_arg (nmc, &argc, &argv, "-mode", &value)) {
			nmc->mode_specified = TRUE;
			if (argc == 1 && nmc->complete)
				complete_option_with_value (argv[0], value, "tabular", "multiline", NULL);
			if (matches (value, "tabular"))
				nmc->nmc_config_mutable.multiline_output = FALSE;
			else if (matches (value, "multiline"))
				nmc->nmc_config_mutable.multiline_output = TRUE;
			else {
				g_string_printf (nmc->return_text, _("Error: '%s' is not a valid argument for '%s' option."), value, argv[0]);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
		} else if (matches_arg (nmc, &argc, &argv, "-colors", &value)) {
			if (argc == 1 && nmc->complete)
				complete_option_with_value (argv[0], value, "yes", "no", "auto", NULL);
			if (matches (value, "auto"))
				nmc->nmc_config_mutable.use_colors = NMC_USE_COLOR_AUTO;
			else if (matches (value, "yes"))
				nmc->nmc_config_mutable.use_colors = NMC_USE_COLOR_YES;
			else if (matches (value, "no"))
				nmc->nmc_config_mutable.use_colors = NMC_USE_COLOR_NO;
			else {
				g_string_printf (nmc->return_text, _("Error: '%s' is not valid argument for '%s' option."), value, argv[0]);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
		} else if (matches_arg (nmc, &argc, &argv, "-escape", &value)) {
			if (argc == 1 && nmc->complete)
				complete_option_with_value (argv[0], value, "yes", "no", NULL);
			if (matches (value, "yes"))
				nmc->nmc_config_mutable.escape_values = TRUE;
			else if (matches (value, "no"))
				nmc->nmc_config_mutable.escape_values = FALSE;
			else {
				g_string_printf (nmc->return_text, _("Error: '%s' is not valid argument for '%s' option."), value, argv[0]);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
		} else if (matches_arg (nmc, &argc, &argv, "-fields", &value)) {
			if (argc == 1 && nmc->complete)
				complete_fields (argv[0], value);
			nmc->required_fields = g_strdup (value);
		} else if (matches_arg (nmc, &argc, &argv, "-get-values", &value)) {
			if (argc == 1 && nmc->complete)
				complete_fields (argv[0], value);
			nmc->required_fields = g_strdup (value);
			nmc->nmc_config_mutable.print_output = NMC_PRINT_TERSE;
			/* We want fixed tabular mode here, but just set the mode specified and rely on the initialization
			 * in nmc_init: in this way we allow use of "-m multiline" to swap the output mode also if placed
			 * before the "-g <field>" option (-g may be still more practical and easy to remember than -t -f).
			*/
			nmc->mode_specified = TRUE;
		} else if (matches_arg (nmc, &argc, &argv, "-nocheck", NULL)) {
			/* ignore for backward compatibility */
		} else if (matches_arg (nmc, &argc, &argv, "-wait", &value)) {
			unsigned long timeout;

			if (!nmc_string_to_uint (value, TRUE, 0, G_MAXINT, &timeout)) {
				g_string_printf (nmc->return_text, _("Error: '%s' is not a valid timeout."), value);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
			nmc->timeout = (int) timeout;
		} else if (matches_arg (nmc, &argc, &argv, "-version", NULL)) {
			if (!nmc->complete)
				g_print (_("nmcli tool, version %s\n"), NMCLI_VERSION);
			return NMC_RESULT_SUCCESS;
		} else if (matches_arg (nmc, &argc, &argv, "-help", NULL)) {
			if (!nmc->complete)
				usage ();
			return NMC_RESULT_SUCCESS;
		} else {
			if (nmc->return_value == NMC_RESULT_SUCCESS) {
				g_string_printf (nmc->return_text, _("Error: Option '%s' is unknown, try 'nmcli -help'."), argv[0]);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			}
			return FALSE;
		}

		next_arg (nmc, &argc, &argv, NULL);
	}

	/* Now run the requested command */
	nmc_do_cmd (nmc, nmcli_cmds, *argv, argc, argv);

	return TRUE;
}

static gboolean nmcli_sigint = FALSE;

gboolean
nmc_seen_sigint (void)
{
	return nmcli_sigint;
}

void
nmc_clear_sigint (void)
{
	nmcli_sigint = FALSE;
}

void nmc_exit (void)
{
	tcsetattr (STDIN_FILENO, TCSADRAIN, &termios_orig);
	nmc_cleanup_readline ();
	exit (1);
}

static gboolean
signal_handler (gpointer user_data)
{
	int signo = GPOINTER_TO_INT (user_data);

	switch (signo) {
	case SIGINT:
		if (nmc_get_in_readline ()) {
			nmcli_sigint = TRUE;
		} else {
			nm_cli.return_value = 0x80 + signo;
			g_string_printf (nm_cli.return_text, _("Error: nmcli terminated by signal %s (%d)"),
			                 strsignal (signo), signo);
			g_main_loop_quit (loop);
		}
		break;
	case SIGTERM:
		nm_cli.return_value = 0x80 + signo;
		g_string_printf (nm_cli.return_text, _("Error: nmcli terminated by signal %s (%d)"),
		                 strsignal (signo), signo);
		nmc_exit ();
		break;
	}

	return G_SOURCE_CONTINUE;
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

/* Initialize NmCli structure - set default values */
static void
nmc_init (NmCli *nmc)
{
	nmc->client = NULL;

	nmc->return_value = NMC_RESULT_SUCCESS;
	nmc->return_text = g_string_new (_("Success"));

	nmc->timeout = -1;

	nmc->secret_agent = NULL;
	nmc->pwds_hash = NULL;
	nmc->pk_listener = NULL;

	nmc->should_wait = 0;
	nmc->nowait_flag = TRUE;
	nmc->nmc_config_mutable.print_output = NMC_PRINT_NORMAL;
	nmc->nmc_config_mutable.multiline_output = FALSE;
	nmc->mode_specified = FALSE;
	nmc->nmc_config_mutable.escape_values = TRUE;
	nmc->required_fields = NULL;
	nmc->ask = FALSE;
	nmc->complete = FALSE;
	nmc->nmc_config_mutable.show_secrets = FALSE;
	nmc->nmc_config_mutable.use_colors = NMC_USE_COLOR_AUTO;
	nmc->nmc_config_mutable.in_editor = FALSE;
	nmc->editor_status_line = FALSE;
	nmc->editor_save_confirmation = TRUE;
	nmc->editor_prompt_color = NM_META_TERM_COLOR_NORMAL;
}

static void
nmc_cleanup (NmCli *nmc)
{
	pid_t ret;

	g_clear_object (&nmc->client);

	g_string_free (nmc->return_text, TRUE);

	if (nmc->secret_agent) {
		/* Destroy secret agent if we have one. */
		nm_secret_agent_old_unregister (nmc->secret_agent, NULL, NULL);
		g_object_unref (nmc->secret_agent);
	}
	if (nmc->pwds_hash)
		g_hash_table_destroy (nmc->pwds_hash);

	g_free (nmc->required_fields);

	if (nmc->pager_pid > 0) {
		fclose (stdout);
		fclose (stderr);
		do {
			ret = waitpid (nmc->pager_pid, NULL, 0);
		} while (ret == -1 && errno == EINTR);
		nmc->pager_pid = 0;
	}

	nmc_polkit_agent_fini (nmc);
}

int
main (int argc, char *argv[])
{
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

	nmc_value_transforms_register ();

	nmc_init (&nm_cli);
	loop = g_main_loop_new (NULL, FALSE);

	g_unix_signal_add (SIGTERM, signal_handler, GINT_TO_POINTER (SIGTERM));
	g_unix_signal_add (SIGINT, signal_handler, GINT_TO_POINTER (SIGINT));

	if (process_command_line (&nm_cli, argc, argv))
		g_main_loop_run (loop);

	if (nm_cli.complete) {
		/* Remove error statuses from command completion runs. */
		if (nm_cli.return_value < NMC_RESULT_COMPLETE_FILE)
			nm_cli.return_value = NMC_RESULT_SUCCESS;
	} else if (nm_cli.return_value != NMC_RESULT_SUCCESS) {
		/* Print result descripting text */
		g_printerr ("%s\n", nm_cli.return_text->str);
	}

	g_main_loop_unref (loop);
	nmc_cleanup (&nm_cli);

	return nm_cli.return_value;
}
