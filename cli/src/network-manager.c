/* nmcli - command-line tool to control NetworkManager
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <glib.h>
#include <glib/gi18n.h>
#include <nm-client.h>
#include <nm-setting-connection.h>

#include "utils.h"
#include "network-manager.h"


/* Available fields for 'nm status' */
static NmcOutputField nmc_fields_nm_status[] = {
	{"RUNNING",        N_("RUNNING"),         15, NULL, 0},  /* 0 */
	{"STATE",          N_("STATE"),           15, NULL, 0},  /* 1 */
	{"WIFI-HARDWARE",  N_("WIFI-HARDWARE"),   15, NULL, 0},  /* 2 */
	{"WIFI",           N_("WIFI"),            10, NULL, 0},  /* 3 */
	{"WWAN-HARDWARE",  N_("WWAN-HARDWARE"),   15, NULL, 0},  /* 4 */
	{"WWAN",           N_("WWAN"),            10, NULL, 0},  /* 5 */
	{NULL,             NULL,                   0, NULL, 0}
};
#define NMC_FIELDS_NM_STATUS_ALL     "RUNNING,STATE,WIFI-HARDWARE,WIFI,WWAN-HARDWARE,WWAN"
#define NMC_FIELDS_NM_STATUS_COMMON  "RUNNING,STATE,WIFI-HARDWARE,WIFI,WWAN-HARDWARE,WWAN"
#define NMC_FIELDS_NM_WIFI           "WIFI"
#define NMC_FIELDS_NM_WWAN           "WWAN"


extern GMainLoop *loop;

/* static function prototypes */
static void usage (void);
static void quit (void);
static const char *nm_state_to_string (NMState state);
static NMCResultCode show_nm_status (NmCli *nmc);


static void
usage (void)
{
	fprintf (stderr,
	 	 _("Usage: nmcli nm { COMMAND | help }\n\n"
		 "  COMMAND := { status | sleep | wakeup | wifi | wwan }\n\n"
		 "  status\n"
		 "  sleep\n"
		 "  wakeup\n"
		 "  wifi [on|off]\n"
		 "  wwan [on|off]\n\n"));
}

/* quit main loop */
static void
quit (void)
{
	g_main_loop_quit (loop);  /* quit main loop */
}

static const char *
nm_state_to_string (NMState state)
{
	switch (state) {
	case NM_STATE_ASLEEP:
		return _("asleep");
	case NM_STATE_CONNECTING:
		return _("connecting");
	case NM_STATE_CONNECTED:
		return _("connected");
	case NM_STATE_DISCONNECTED:
		return _("disconnected");
	case NM_STATE_UNKNOWN:
	default:
		return _("unknown");
	}
}

static NMCResultCode
show_nm_status (NmCli *nmc)
{
	gboolean nm_running;
	NMState state;
	const char *wireless_hw_enabled_str, *wireless_enabled_str;
	const char *wwan_hw_enabled_str, *wwan_enabled_str;
	GError *error = NULL;
	const char *fields_str;
	const char *fields_all =    NMC_FIELDS_NM_STATUS_ALL;
	const char *fields_common = NMC_FIELDS_NM_STATUS_COMMON;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	g_return_val_if_fail (nmc->client != NULL, NMC_RESULT_ERROR_UNKNOWN);

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else 
		fields_str = nmc->required_fields;

	nmc->allowed_fields = nmc_fields_nm_status;
	nmc->print_fields.indices = parse_output_fields (fields_str, nmc->allowed_fields, &error);

	if (error) {
		if (error->code == 0)
			g_string_printf (nmc->return_text, _("Error: 'nm status': %s"), error->message);
		else
			g_string_printf (nmc->return_text, _("Error: 'nm status': %s; allowed fields: %s"), error->message, NMC_FIELDS_NM_STATUS_ALL);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return nmc->return_value;
	}

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ADD | NMC_PF_FLAG_FIELD_NAMES;
	nmc->print_fields.header_name = _("NetworkManager status");
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

	nm_running = nm_client_get_manager_running (nmc->client);
	state = nm_client_get_state (nmc->client);
	if (nm_running) {
		wireless_hw_enabled_str = nm_client_wireless_hardware_get_enabled (nmc->client) ? _("enabled") : _("disabled");
		wireless_enabled_str = nm_client_wireless_get_enabled (nmc->client) ? _("enabled") : _("disabled");
		wwan_hw_enabled_str = nm_client_wwan_hardware_get_enabled (nmc->client) ? _("enabled") : _("disabled");
		wwan_enabled_str = nm_client_wwan_get_enabled (nmc->client) ? _("enabled") : _("disabled");
	} else {
		wireless_hw_enabled_str = wireless_enabled_str = wwan_hw_enabled_str = wwan_enabled_str = _("unknown");
	}

	nmc->allowed_fields[0].value = nm_running ? _("running") : _("not running");
	nmc->allowed_fields[1].value = nm_state_to_string (state);
	nmc->allowed_fields[2].value = wireless_hw_enabled_str;
	nmc->allowed_fields[3].value = wireless_enabled_str;
	nmc->allowed_fields[4].value = wwan_hw_enabled_str;
	nmc->allowed_fields[5].value = wwan_enabled_str;

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	return NMC_RESULT_SUCCESS;
}


/* entry point function for global network manager related commands 'nmcli nm' */
NMCResultCode
do_network_manager (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;
	gboolean enable_wifi;
	gboolean enable_wwan;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	/* create NMClient */
	if (!nmc->get_client (nmc))
		goto end;

	if (argc == 0) {
		if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
			goto opt_error;
		nmc->return_value = show_nm_status (nmc);
	}

	if (argc > 0) {
		if (matches (*argv, "status") == 0) {
			if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
				goto opt_error;
			nmc->return_value = show_nm_status (nmc);
		}
		else if (matches (*argv, "sleep") == 0) {
			nm_client_sleep (nmc->client, TRUE);		
		}
		else if (matches (*argv, "wakeup") == 0) {
			nm_client_sleep (nmc->client, FALSE);
		}
		else if (matches (*argv, "wifi") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				/* no argument, show current WiFi state */
				if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
					goto opt_error;
				if (nmc->required_fields && strcasecmp (nmc->required_fields, "WIFI")) {
					g_string_printf (nmc->return_text, _("Error: '--fields' value '%s' is not valid here; allowed fields: %s"),
					                 nmc->required_fields, NMC_FIELDS_NM_WIFI);
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					goto end;
				}
				nmc->allowed_fields = nmc_fields_nm_status;
				nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_NM_WIFI, nmc->allowed_fields, NULL);
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ADD | NMC_PF_FLAG_FIELD_NAMES;
				nmc->print_fields.header_name = _("WiFi enabled");
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */
				nmc->allowed_fields[3].value = nm_client_wireless_get_enabled (nmc->client) ? _("enabled") : _("disabled");
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag;
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */
			} else {
				if (!strcmp (*argv, "on"))
					enable_wifi = TRUE;
				else if (!strcmp (*argv, "off"))
					enable_wifi = FALSE;
				else {
					g_string_printf (nmc->return_text, _("Error: invalid 'wifi' parameter: '%s'."), *argv);
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					goto end;
				}
				nm_client_wireless_set_enabled (nmc->client, enable_wifi);
			}
		}
		else if (matches (*argv, "wwan") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
					goto opt_error;
				/* no argument, show current WWAN state */
				if (nmc->required_fields && strcasecmp (nmc->required_fields, "WWAN")) {
					g_string_printf (nmc->return_text, _("Error: '--fields' value '%s' is not valid here; allowed fields: %s"),
					                 nmc->required_fields, NMC_FIELDS_NM_WWAN);
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					goto end;
				}
				nmc->allowed_fields = nmc_fields_nm_status;
				nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_NM_WWAN, nmc->allowed_fields, NULL);
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ADD | NMC_PF_FLAG_FIELD_NAMES;
				nmc->print_fields.header_name = _("WWAN enabled");
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */
				nmc->allowed_fields[5].value = nm_client_wwan_get_enabled (nmc->client) ? _("enabled") : _("disabled");
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag;
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */
			} else {
				if (!strcmp (*argv, "on"))
					enable_wwan = TRUE;
				else if (!strcmp (*argv, "off"))
					enable_wwan = FALSE;
				else {
					g_string_printf (nmc->return_text, _("Error: invalid 'wwan' parameter: '%s'."), *argv);
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					goto end;
				}
				nm_client_wwan_set_enabled (nmc->client, enable_wwan);
			}
		}
		else if (strcmp (*argv, "help") == 0) {
			usage ();
		}
		else {
			g_string_printf (nmc->return_text, _("Error: 'nm' command '%s' is not valid."), *argv);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		}
	}

end:
	quit ();
	return nmc->return_value;

opt_error:
	quit ();
	g_string_printf (nmc->return_text, _("Error: %s."), error->message);
	nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
	g_error_free (error);
	return nmc->return_value;
}
