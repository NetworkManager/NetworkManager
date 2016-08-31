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

#include "nm-default.h"

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

#include "polkit-agent.h"
#include "nmcli.h"
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
struct termios termios_orig;

static void
complete_field (GHashTable *h, const char *setting, NmcOutputField field[])
{
	int i;

	for (i = 0; field[i].name; i++) {
		if (setting)
			g_hash_table_add (h, g_strdup_printf ("%s.%s", setting, field[i].name));
		else
			g_hash_table_add (h, g_strdup (field[i].name));
	}
}

static void
complete_one (gpointer key, gpointer value, gpointer user_data)
{
	const char *prefix = user_data;
	const char *name = key;
	const char *last;

	last = strrchr (prefix, ',');
	if (last)
		last++;
	else
		last = prefix;

	if ((!*last && !strchr (name, '.')) || matches (last, name) == 0) {
		g_print ("%.*s%s%s\n", (int)(last-prefix), prefix, name,
		                       strcmp (last, name) == 0 ? "," : "");
	}
}

static void
complete_fields (const char *prefix)
{

	GHashTable *h;

	h = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

	complete_field (h, NULL, nmc_fields_ip4_config);
	complete_field (h, NULL, nmc_fields_dhcp4_config);
	complete_field (h, NULL, nmc_fields_ip6_config);
	complete_field (h, NULL, nmc_fields_dhcp6_config);
	complete_field (h, NULL, nmc_fields_con_show);
	complete_field (h, NULL, nmc_fields_settings_names);
	complete_field (h, NULL, nmc_fields_con_active_details_general);
	complete_field (h, NULL, nmc_fields_con_active_details_vpn);
	complete_field (h, NULL, nmc_fields_con_active_details_groups);
	complete_field (h, NULL, nmc_fields_dev_status);
	complete_field (h, NULL, nmc_fields_dev_show_general);
	complete_field (h, NULL, nmc_fields_dev_show_connections);
	complete_field (h, NULL, nmc_fields_dev_show_cap);
	complete_field (h, NULL, nmc_fields_dev_show_wired_prop);
	complete_field (h, NULL, nmc_fields_dev_show_wifi_prop);
	complete_field (h, NULL, nmc_fields_dev_show_wimax_prop);
	complete_field (h, NULL, nmc_fields_dev_wifi_list);
	complete_field (h, NULL, nmc_fields_dev_wimax_list);
	complete_field (h, NULL, nmc_fields_dev_show_master_prop);
	complete_field (h, NULL, nmc_fields_dev_show_team_prop);
	complete_field (h, NULL, nmc_fields_dev_show_vlan_prop);
	complete_field (h, NULL, nmc_fields_dev_show_bluetooth);
	complete_field (h, NULL, nmc_fields_dev_show_sections);
	complete_field (h, NULL, nmc_fields_dev_lldp_list);

	complete_field (h, "connection", nmc_fields_setting_connection);
	complete_field (h, "wired", nmc_fields_setting_wired);
	complete_field (h, "8021X", nmc_fields_setting_8021X);
	complete_field (h, "wireless", nmc_fields_setting_wireless);
	complete_field (h, "wireless_security", nmc_fields_setting_wireless_security);
	complete_field (h, "ip4-config", nmc_fields_setting_ip4_config);
	complete_field (h, "ip6-config", nmc_fields_setting_ip6_config);
	complete_field (h, "serial", nmc_fields_setting_serial);
	complete_field (h, "ppp", nmc_fields_setting_ppp);
	complete_field (h, "pppoe", nmc_fields_setting_pppoe);
	complete_field (h, "adsl", nmc_fields_setting_adsl);
	complete_field (h, "gsm", nmc_fields_setting_gsm);
	complete_field (h, "cdma", nmc_fields_setting_cdma);
	complete_field (h, "bluetooth", nmc_fields_setting_bluetooth);
	complete_field (h, "olpc-mesh", nmc_fields_setting_olpc_mesh);
	complete_field (h, "vpn", nmc_fields_setting_vpn);
	complete_field (h, "wimax", nmc_fields_setting_wimax);
	complete_field (h, "infiniband", nmc_fields_setting_infiniband);
	complete_field (h, "bond", nmc_fields_setting_bond);
	complete_field (h, "vlan", nmc_fields_setting_vlan);
	complete_field (h, "bridge", nmc_fields_setting_bridge);
	complete_field (h, "bridge-port", nmc_fields_setting_bridge_port);
	complete_field (h, "team", nmc_fields_setting_team);
	complete_field (h, "team0port", nmc_fields_setting_team_port);
	complete_field (h, "dcb", nmc_fields_setting_dcb);
	complete_field (h, "tun", nmc_fields_setting_tun);
	complete_field (h, "ip-tunnel", nmc_fields_setting_ip_tunnel);
	complete_field (h, "macvlan", nmc_fields_setting_macvlan);
	complete_field (h, "vxlan", nmc_fields_setting_vxlan);

	g_hash_table_foreach (h, complete_one, (gpointer) prefix);
	g_hash_table_destroy (h);
}


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
usage (void)
{
	g_printerr (_("Usage: nmcli [OPTIONS] OBJECT { COMMAND | help }\n"
	              "\n"
	              "OPTIONS\n"
	              "  -t[erse]                                   terse output\n"
	              "  -p[retty]                                  pretty output\n"
	              "  -m[ode] tabular|multiline                  output mode\n"
	              "  -c[olors] auto|yes|no                      whether to use colors in output\n"
	              "  -f[ields] <field1,field2,...>|all|common   specify fields to output\n"
	              "  -e[scape] yes|no                           escape columns separators in values\n"
	              "  -a[sk]                                     ask for missing parameters\n"
	              "  -s[how-secrets]                            allow displaying passwords\n"
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
		argc--; argv++;
	}
	argc--; argv++;

	/* parse options */
	while (argc) {
		char *opt = argv[0];
		if (opt[0] != '-')
			break;

		if (argc == 1 && nmc->complete) {
			nmc_complete_strings (opt, "--terse", "--pretty", "--mode", "--colors", "--escape",
			                           "--fields", "--nocheck", "--ask", "--show-secrets",
			                           "--wait", "--version", "--help", NULL);
		}

		if (opt[1] == '-') {
			opt++;
			/* '--' ends options */
			if (opt[1] == '\0') {
				argc--; argv++;
				break;
			}
		}

		if (matches (opt, "-terse") == 0) {
			if (nmc->print_output == NMC_PRINT_TERSE) {
				g_string_printf (nmc->return_text, _("Error: Option '--terse' is specified the second time."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
			else if (nmc->print_output == NMC_PRINT_PRETTY) {
				g_string_printf (nmc->return_text, _("Error: Option '--terse' is mutually exclusive with '--pretty'."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
			else
				nmc->print_output = NMC_PRINT_TERSE;
		} else if (matches (opt, "-pretty") == 0) {
			if (nmc->print_output == NMC_PRINT_PRETTY) {
				g_string_printf (nmc->return_text, _("Error: Option '--pretty' is specified the second time."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
			else if (nmc->print_output == NMC_PRINT_TERSE) {
				g_string_printf (nmc->return_text, _("Error: Option '--pretty' is mutually exclusive with '--terse'."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
			else
				nmc->print_output = NMC_PRINT_PRETTY;
		} else if (matches (opt, "-mode") == 0) {
			nmc->mode_specified = TRUE;
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: missing argument for '%s' option."), opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
			if (argc == 1 && nmc->complete)
				nmc_complete_strings (argv[0], "tabular", "multiline", NULL);
			if (matches (argv[0], "tabular") == 0)
				nmc->multiline_output = FALSE;
			else if (matches (argv[0], "multiline") == 0)
				nmc->multiline_output = TRUE;
			else {
				g_string_printf (nmc->return_text, _("Error: '%s' is not valid argument for '%s' option."), argv[0], opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
		} else if (matches (opt, "-colors") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: missing argument for '%s' option."), opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
			if (argc == 1 && nmc->complete)
				nmc_complete_strings (argv[0], "yes", "no", "auto", NULL);
			if (matches (argv[0], "auto") == 0)
				nmc->use_colors = NMC_USE_COLOR_AUTO;
			else if (matches (argv[0], "yes") == 0)
				nmc->use_colors = NMC_USE_COLOR_YES;
			else if (matches (argv[0], "no") == 0)
				nmc->use_colors = NMC_USE_COLOR_NO;
			else {
				g_string_printf (nmc->return_text, _("Error: '%s' is not valid argument for '%s' option."), argv[0], opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
		} else if (matches (opt, "-escape") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: missing argument for '%s' option."), opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
			if (argc == 1 && nmc->complete)
				nmc_complete_strings (argv[0], "yes", "no", NULL);
			if (matches (argv[0], "yes") == 0)
				nmc->escape_values = TRUE;
			else if (matches (argv[0], "no") == 0)
				nmc->escape_values = FALSE;
			else {
				g_string_printf (nmc->return_text, _("Error: '%s' is not valid argument for '%s' option."), argv[0], opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
		} else if (matches (opt, "-fields") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: fields for '%s' options are missing."), opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
			if (argc == 1 && nmc->complete)
				complete_fields (argv[0]);
			nmc->required_fields = g_strdup (argv[0]);
		} else if (matches (opt, "-nocheck") == 0) {
			/* ignore for backward compatibility */
		} else if (matches (opt, "-ask") == 0) {
			nmc->ask = TRUE;
		} else if (matches (opt, "-show-secrets") == 0) {
			nmc->show_secrets = TRUE;
		} else if (matches (opt, "-wait") == 0) {
			unsigned long timeout;
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: missing argument for '%s' option."), opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
			if (!nmc_string_to_uint (argv[0], TRUE, 0, G_MAXINT, &timeout)) {
				g_string_printf (nmc->return_text, _("Error: '%s' is not a valid timeout for '%s' option."),
						 argv[0], opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return FALSE;
			}
			nmc->timeout = (int) timeout;
		} else if (matches (opt, "-version") == 0) {
			if (!nmc->complete)
				g_print (_("nmcli tool, version %s\n"), NMCLI_VERSION);
			return NMC_RESULT_SUCCESS;
		} else if (matches (opt, "-help") == 0) {
			if (!nmc->complete)
				usage ();
			return NMC_RESULT_SUCCESS;
		} else {
			g_string_printf (nmc->return_text, _("Error: Option '%s' is unknown, try 'nmcli -help'."), opt);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			return FALSE;
		}
		argc--;
		argv++;
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
			g_print (_("Error: nmcli terminated by signal %s (%d)\n"),
			         strsignal (signo),
			         signo);
			g_main_loop_quit (loop);
		}
		break;
	case SIGTERM:
		g_print (_("Error: nmcli terminated by signal %s (%d)\n"),
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
	nmc->print_output = NMC_PRINT_NORMAL;
	nmc->multiline_output = FALSE;
	nmc->mode_specified = FALSE;
	nmc->escape_values = TRUE;
	nmc->required_fields = NULL;
	nmc->output_data = g_ptr_array_new_full (20, g_free);
	memset (&nmc->print_fields, '\0', sizeof (NmcPrintFields));
	nmc->ask = FALSE;
	nmc->complete = FALSE;
	nmc->show_secrets = FALSE;
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

	g_unix_signal_add (SIGTERM, signal_handler, GINT_TO_POINTER (SIGTERM));
	g_unix_signal_add (SIGINT, signal_handler, GINT_TO_POINTER (SIGINT));

	nmc_value_transforms_register ();

	nmc_init (&nm_cli);
	loop = g_main_loop_new (NULL, FALSE);
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
