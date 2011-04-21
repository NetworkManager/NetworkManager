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
 * (C) Copyright 2010 - 2011 Red Hat, Inc.
 */

#include "config.h"

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
	{"VERSION",        N_("VERSION"),         10, NULL, 0},  /* 1 */
	{"STATE",          N_("STATE"),           15, NULL, 0},  /* 2 */
	{"NET-ENABLED",    N_("NET-ENABLED"),     13, NULL, 0},  /* 3 */
	{"WIFI-HARDWARE",  N_("WIFI-HARDWARE"),   15, NULL, 0},  /* 4 */
	{"WIFI",           N_("WIFI"),            10, NULL, 0},  /* 5 */
	{"WWAN-HARDWARE",  N_("WWAN-HARDWARE"),   15, NULL, 0},  /* 6 */
	{"WWAN",           N_("WWAN"),            10, NULL, 0},  /* 7 */
	{"WIMAX-HARDWARE", N_("WIMAX-HARDWARE"),  15, NULL, 0},  /* 8 */
	{"WIMAX",          N_("WIMAX"),           10, NULL, 0},  /* 9 */
	{NULL,             NULL,                  0, NULL, 0}
};
#if WITH_WIMAX
#define NMC_FIELDS_NM_STATUS_ALL     "RUNNING,VERSION,STATE,NET-ENABLED,WIFI-HARDWARE,WIFI,WWAN-HARDWARE,WWAN,WIMAX-HARDWARE,WIMAX"
#else
#define NMC_FIELDS_NM_STATUS_ALL     "RUNNING,VERSION,STATE,NET-ENABLED,WIFI-HARDWARE,WIFI,WWAN-HARDWARE,WWAN"
#endif
#define NMC_FIELDS_NM_STATUS_COMMON  "RUNNING,STATE,WIFI-HARDWARE,WIFI,WWAN-HARDWARE,WWAN"
#define NMC_FIELDS_NM_NET_ENABLED    "NET-ENABLED"
#define NMC_FIELDS_NM_WIFI           "WIFI"
#define NMC_FIELDS_NM_WWAN           "WWAN"
#define NMC_FIELDS_NM_WIMAX          "WIMAX"


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
#if WITH_WIMAX
	         "  COMMAND := { status | enable | sleep | wifi | wwan | wimax }\n\n"
#else
	         "  COMMAND := { status | enable | sleep | wifi | wwan }\n\n"
#endif
	         "  status\n"
	         "  enable [true|false]\n"
	         "  sleep [true|false]\n"
	         "  wifi [on|off]\n"
	         "  wwan [on|off]\n"
#if WITH_WIMAX
	         "  wimax [on|off]\n\n"
#endif
	         ));
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
	case NM_STATE_CONNECTED_LOCAL:
		return _("connected (local only)");
	case NM_STATE_CONNECTED_SITE:
		return _("connected (site only)");
	case NM_STATE_CONNECTED_GLOBAL:
		return _("connected");
	case NM_STATE_DISCONNECTING:
		return _("disconnecting");
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
	NMState state = NM_STATE_UNKNOWN;
	const char *net_enabled_str;
	const char *wireless_hw_enabled_str, *wireless_enabled_str;
	const char *wwan_hw_enabled_str, *wwan_enabled_str;
#if WITH_WIMAX
	const char *wimax_hw_enabled_str, *wimax_enabled_str;
#endif
	GError *error = NULL;
	const char *fields_str;
	const char *fields_all =    NMC_FIELDS_NM_STATUS_ALL;
	const char *fields_common = NMC_FIELDS_NM_STATUS_COMMON;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

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

	nm_running = nmc_is_nm_running (nmc, NULL);
	if (nm_running) {
		if (!nmc_versions_match (nmc))
			goto error;

		nmc->get_client (nmc); /* create NMClient */
		state = nm_client_get_state (nmc->client);
		net_enabled_str = nm_client_networking_get_enabled (nmc->client) ? _("enabled") : _("disabled");
		wireless_hw_enabled_str = nm_client_wireless_hardware_get_enabled (nmc->client) ? _("enabled") : _("disabled");
		wireless_enabled_str = nm_client_wireless_get_enabled (nmc->client) ? _("enabled") : _("disabled");
		wwan_hw_enabled_str = nm_client_wwan_hardware_get_enabled (nmc->client) ? _("enabled") : _("disabled");
		wwan_enabled_str = nm_client_wwan_get_enabled (nmc->client) ? _("enabled") : _("disabled");
#if WITH_WIMAX
		wimax_hw_enabled_str = nm_client_wimax_hardware_get_enabled (nmc->client) ? _("enabled") : _("disabled");
		wimax_enabled_str = nm_client_wimax_get_enabled (nmc->client) ? _("enabled") : _("disabled");
#endif
	} else {
#if WITH_WIMAX
		net_enabled_str = wireless_hw_enabled_str = wireless_enabled_str =
		wwan_hw_enabled_str = wwan_enabled_str = wimax_hw_enabled_str = wimax_enabled_str = _("unknown");
#else
		net_enabled_str = wireless_hw_enabled_str = wireless_enabled_str =
		wwan_hw_enabled_str = wwan_enabled_str = _("unknown");
#endif
	}

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ADD | NMC_PF_FLAG_FIELD_NAMES;
	nmc->print_fields.header_name = _("NetworkManager status");
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

	nmc->allowed_fields[0].value = nm_running ? _("running") : _("not running");
	nmc->allowed_fields[1].value = nm_running ? nm_client_get_version (nmc->client) : _("unknown");
	nmc->allowed_fields[2].value = nm_state_to_string (state);
	nmc->allowed_fields[3].value = net_enabled_str;
	nmc->allowed_fields[4].value = wireless_hw_enabled_str;
	nmc->allowed_fields[5].value = wireless_enabled_str;
	nmc->allowed_fields[6].value = wwan_hw_enabled_str;
	nmc->allowed_fields[7].value = wwan_enabled_str;
#if WITH_WIMAX
	nmc->allowed_fields[8].value = wimax_hw_enabled_str;
	nmc->allowed_fields[9].value = wimax_enabled_str;
#endif

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	return NMC_RESULT_SUCCESS;

error:
	return nmc->return_value;
}

/* libnm-glib doesn't provide API fro Sleep method - implement D-Bus call ourselves */
static void networking_set_sleep (NmCli *nmc, gboolean in_sleep)
{
	DBusGConnection *connection = NULL;
	DBusGProxy *proxy = NULL;
	GError *err = NULL;

	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!connection) {
		g_string_printf (nmc->return_text, _("Error: Couldn't connect to system bus: %s"), err->message);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
        	g_error_free (err);
	        goto gone;
	}

	proxy = dbus_g_proxy_new_for_name (connection,
	                                   "org.freedesktop.NetworkManager",
	                                   "/org/freedesktop/NetworkManager",
	                                   "org.freedesktop.NetworkManager");
	if (!proxy) {
		g_string_printf (nmc->return_text, _("Error: Couldn't create D-Bus object proxy."));
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto gone;
        }
 
	if (!dbus_g_proxy_call (proxy, "Sleep", &err, G_TYPE_BOOLEAN, in_sleep, G_TYPE_INVALID, G_TYPE_INVALID)) {
		g_string_printf (nmc->return_text, _("Error in sleep: %s"), err->message);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		g_error_free (err);
	}

gone:
	if (connection) dbus_g_connection_unref (connection);
	if (proxy) g_object_unref (proxy);
}

/* entry point function for global network manager related commands 'nmcli nm' */
NMCResultCode
do_network_manager (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;
	gboolean sleep_flag;
	gboolean enable_net;
	gboolean enable_wifi;
	gboolean enable_wwan;
#if WITH_WIMAX
	gboolean enable_wimax;
#endif
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

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
		else if (matches (*argv, "enable") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				/* no argument, show current state of networking */
				if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
					goto opt_error;
				if (nmc->required_fields && strcasecmp (nmc->required_fields, "NET-ENABLED")) {
					g_string_printf (nmc->return_text, _("Error: '--fields' value '%s' is not valid here; allowed fields: %s"),
					                 nmc->required_fields, NMC_FIELDS_NM_NET_ENABLED);
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					goto end;
				}
				nmc->allowed_fields = nmc_fields_nm_status;
				nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_NM_NET_ENABLED, nmc->allowed_fields, NULL);
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ADD | NMC_PF_FLAG_FIELD_NAMES;
				nmc->print_fields.header_name = _("Networking enabled");
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

				if (nmc_is_nm_running (nmc, NULL)) {
					nmc->get_client (nmc); /* create NMClient */
					nmc->allowed_fields[3].value = nm_client_networking_get_enabled (nmc->client) ? _("enabled") : _("disabled");
				} else
					nmc->allowed_fields[3].value = _("unknown");
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag;
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */
			} else {
				if (!strcmp (*argv, "true"))
					enable_net = TRUE;
				else if (!strcmp (*argv, "false"))
					enable_net = FALSE;
				else {
					g_string_printf (nmc->return_text, _("Error: invalid 'enable' parameter: '%s'; use 'true' or 'false'."), *argv);
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					goto end;
				}
				nmc->get_client (nmc); /* create NMClient */
				nm_client_networking_set_enabled (nmc->client, enable_net);
			}
		}
		else if (matches (*argv, "sleep") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: Sleeping status is not exported by NetworkManager."));
				nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			} else {
				if (!strcmp (*argv, "true"))
					sleep_flag = TRUE;
				else if (!strcmp (*argv, "false"))
					sleep_flag = FALSE;
				else {
					g_string_printf (nmc->return_text, _("Error: invalid 'sleep' parameter: '%s'; use 'true' or 'false'."), *argv);
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					goto end;
				}
				networking_set_sleep (nmc, sleep_flag);
			}
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

				if (nmc_is_nm_running (nmc, NULL)) {
					nmc->get_client (nmc); /* create NMClient */
					nmc->allowed_fields[5].value = nm_client_wireless_get_enabled (nmc->client) ? _("enabled") : _("disabled");
				} else
					nmc->allowed_fields[5].value = _("unknown");
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag;
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */
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
				nmc->get_client (nmc); /* create NMClient */
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

				if (nmc_is_nm_running (nmc, NULL)) {
					nmc->get_client (nmc); /* create NMClient */
					nmc->allowed_fields[7].value = nm_client_wwan_get_enabled (nmc->client) ? _("enabled") : _("disabled");
				} else
					nmc->allowed_fields[7].value = _("unknown");
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag;
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */
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
				nmc->get_client (nmc); /* create NMClient */
				nm_client_wwan_set_enabled (nmc->client, enable_wwan);
			}
		}
#if WITH_WIMAX
		else if (matches (*argv, "wimax") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
					goto opt_error;
				/* no argument, show current WiMAX state */
				if (nmc->required_fields && strcasecmp (nmc->required_fields, "WIMAX")) {
					g_string_printf (nmc->return_text, _("Error: '--fields' value '%s' is not valid here; allowed fields: %s"),
					                 nmc->required_fields, NMC_FIELDS_NM_WIMAX);
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					goto end;
				}
				nmc->allowed_fields = nmc_fields_nm_status;
				nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_NM_WIMAX, nmc->allowed_fields, NULL);
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ADD | NMC_PF_FLAG_FIELD_NAMES;
				nmc->print_fields.header_name = _("WiMAX enabled");
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

				if (nmc_is_nm_running (nmc, NULL)) {
					nmc->get_client (nmc); /* create NMClient */
					nmc->allowed_fields[9].value = nm_client_wimax_get_enabled (nmc->client) ? _("enabled") : _("disabled");
				} else
					nmc->allowed_fields[9].value = _("unknown");
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag;
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */
			} else {
				if (!strcmp (*argv, "on"))
					enable_wimax = TRUE;
				else if (!strcmp (*argv, "off"))
					enable_wimax = FALSE;
				else {
					g_string_printf (nmc->return_text, _("Error: invalid 'wimax' parameter: '%s'."), *argv);
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					goto end;
				}
				nmc->get_client (nmc); /* create NMClient */
				nm_client_wimax_set_enabled (nmc->client, enable_wimax);
			}
		}
#endif
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
