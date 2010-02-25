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

	g_return_val_if_fail (nmc->client != NULL, NMC_RESULT_ERROR_UNKNOWN);

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

	if (nmc->print_output == NMC_PRINT_PRETTY)
		print_table_header (_("NetworkManager status"), NULL);

	print_table_line (0, _("NM running:"), 25, nm_running ? _("running") : _("not running"), 0, NULL);
	print_table_line (0, _("NM state:"), 25, nm_state_to_string (state), 0, NULL);
	print_table_line (0, _("NM wireless hardware:"), 25, wireless_hw_enabled_str, 0, NULL);
	print_table_line (0, _("NM wireless:"), 25, wireless_enabled_str, 0, NULL);
	print_table_line (0, _("NM WWAN hardware:"), 25, wwan_hw_enabled_str, 0, NULL);
	print_table_line (0, _("NM WWAN:"), 25, wwan_enabled_str, 0, NULL);

	return NMC_RESULT_SUCCESS;
}


/* entry point function for global network manager related commands 'nmcli nm' */
NMCResultCode
do_network_manager (NmCli *nmc, int argc, char **argv)
{
	gboolean enable_wifi;
	gboolean enable_wwan;

	/* create NMClient */
	if (!nmc->get_client (nmc))
		goto end;

	if (argc == 0) {
		nmc->return_value = show_nm_status (nmc);
	}

	if (argc > 0) {
		if (matches (*argv, "status") == 0) {
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
				/* no argument, show current state */
				print_table_line (0, _("NM wireless:"), 25, nm_client_wireless_get_enabled (nmc->client) ? _("enabled") : _("disabled"), 0, NULL);
			} else {
				if (!strcmp (*argv, "on"))
					enable_wifi = TRUE;
				else if (!strcmp (*argv, "off"))
					enable_wifi = FALSE;
				else {
					g_string_printf (nmc->return_text, _("Error: invalid 'wifi' parameter: '%s'."), *argv);
					nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
					goto end;
				}
				nm_client_wireless_set_enabled (nmc->client, enable_wifi);
			}
		}
		else if (matches (*argv, "wwan") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				/* no argument, show current state */
				print_table_line (0, _("NM WWAN:"), 25, nm_client_wwan_get_enabled (nmc->client) ? _("enabled") : _("disabled"), 0, NULL);
			} else {
				if (!strcmp (*argv, "on"))
					enable_wwan = TRUE;
				else if (!strcmp (*argv, "off"))
					enable_wwan = FALSE;
				else {
					g_string_printf (nmc->return_text, _("Error: invalid 'wwan' parameter: '%s'."), *argv);
					nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
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
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		}
	}

end:
	quit ();
	return nmc->return_value;
}
