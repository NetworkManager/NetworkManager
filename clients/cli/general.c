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
 * Copyright 2010 - 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <stdlib.h>

#include "polkit-agent.h"
#include "utils.h"
#include "common.h"
#include "general.h"
#include "common.h"
#include "nm-common-macros.h"

#include "devices.h"
#include "connections.h"

/* Available fields for 'general status' */
static NmcOutputField nmc_fields_nm_status[] = {
	{"RUNNING",      N_("RUNNING")},       /* 0 */
	{"VERSION",      N_("VERSION")},       /* 1 */
	{"STATE",        N_("STATE")},         /* 2 */
	{"STARTUP",      N_("STARTUP")},       /* 3 */
	{"CONNECTIVITY", N_("CONNECTIVITY")},  /* 4 */
	{"NETWORKING",   N_("NETWORKING")},    /* 5 */
	{"WIFI-HW",      N_("WIFI-HW")},       /* 6 */
	{"WIFI",         N_("WIFI")},          /* 7 */
	{"WWAN-HW",      N_("WWAN-HW")},       /* 8 */
	{"WWAN",         N_("WWAN")},          /* 9 */
	{"WIMAX-HW",     N_("WIMAX-HW")},      /* 10 */
	{"WIMAX",        N_("WIMAX")},         /* 11 */
	{NULL, NULL}
};
#define NMC_FIELDS_NM_STATUS_ALL     "RUNNING,VERSION,STATE,STARTUP,CONNECTIVITY,NETWORKING,WIFI-HW,WIFI,WWAN-HW,WWAN"
#define NMC_FIELDS_NM_STATUS_SWITCH  "NETWORKING,WIFI-HW,WIFI,WWAN-HW,WWAN"
#define NMC_FIELDS_NM_STATUS_RADIO   "WIFI-HW,WIFI,WWAN-HW,WWAN"
#define NMC_FIELDS_NM_STATUS_COMMON  "STATE,CONNECTIVITY,WIFI-HW,WIFI,WWAN-HW,WWAN"
#define NMC_FIELDS_NM_NETWORKING     "NETWORKING"
#define NMC_FIELDS_NM_WIFI           "WIFI"
#define NMC_FIELDS_NM_WWAN           "WWAN"
#define NMC_FIELDS_NM_WIMAX          "WIMAX"
#define NMC_FIELDS_NM_CONNECTIVITY   "CONNECTIVITY"


/* Available fields for 'general permissions' */
static NmcOutputField nmc_fields_nm_permissions[] = {
	{"PERMISSION", N_("PERMISSION")},  /* 0 */
	{"VALUE",      N_("VALUE")},       /* 1 */
	{NULL, NULL}
};
#define NMC_FIELDS_NM_PERMISSIONS_ALL     "PERMISSION,VALUE"
#define NMC_FIELDS_NM_PERMISSIONS_COMMON  "PERMISSION,VALUE"

/* Available fields for 'general logging' */
static NmcOutputField nmc_fields_nm_logging[] = {
	{"LEVEL",   N_("LEVEL")},    /* 0 */
	{"DOMAINS", N_("DOMAINS")},  /* 1 */
	{NULL, NULL}
};
#define NMC_FIELDS_NM_LOGGING_ALL     "LEVEL,DOMAINS"
#define NMC_FIELDS_NM_LOGGING_COMMON  "LEVEL,DOMAINS"


/* glib main loop variable - defined in nmcli.c */
extern GMainLoop *loop;


static void
usage_general (void)
{
	g_printerr (_("Usage: nmcli general { COMMAND | help }\n\n"
	              "COMMAND := { status | hostname | permissions | logging }\n\n"
	              "  status\n\n"
	              "  hostname [<hostname>]\n\n"
	              "  permissions\n\n"
	              "  logging [level <log level>] [domains <log domains>]\n\n"));
}

static void
usage_general_status (void)
{
	g_printerr (_("Usage: nmcli general status { help }\n"
	              "\n"
	              "Show overall status of NetworkManager.\n"
	              "'status' is the default action, which means 'nmcli gen' calls 'nmcli gen status'\n\n"));
}

static void
usage_general_hostname (void)
{
	g_printerr (_("Usage: nmcli general hostname { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [<hostname>]\n"
	              "\n"
	              "Get or change persistent system hostname.\n"
	              "With no arguments, this prints currently configured hostname. When you pass\n"
	              "a hostname, NetworkManager will set it as the new persistent system hostname.\n\n"));
}

static void
usage_general_permissions (void)
{
	g_printerr (_("Usage: nmcli general permissions { help }\n"
	              "\n"
	              "Show caller permissions for authenticated operations.\n\n"));
}

static void
usage_general_logging (void)
{
	g_printerr (_("Usage: nmcli general logging { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [level <log level>] [domains <log domains>]\n"
	              "\n"
	              "Get or change NetworkManager logging level and domains.\n"
	              "Without any argument current logging level and domains are shown. In order to\n"
	              "change logging state, provide level and/or domain. Please refer to the man page\n"
	              "for the list of possible logging domains.\n\n"));
}

static void
usage_networking (void)
{
	g_printerr (_("Usage: nmcli networking { COMMAND | help }\n\n"
	              "COMMAND := { [ on | off | connectivity ] }\n\n"
	              "  on\n\n"
	              "  off\n\n"
	              "  connectivity [check]\n\n"));
}

static void
usage_networking_on (void)
{
	g_printerr (_("Usage: nmcli networking on { help }\n"
	              "\n"
	              "Switch networking on.\n\n"));
}

static void
usage_networking_off (void)
{
	g_printerr (_("Usage: nmcli networking off { help }\n"
	              "\n"
	              "Switch networking off.\n\n"));
}

static void
usage_networking_connectivity (void)
{
	g_printerr (_("Usage: nmcli networking connectivity { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [check]\n"
	              "\n"
	              "Get network connectivity state.\n"
	              "The optional 'check' argument makes NetworkManager re-check the connectivity.\n\n"));

}

static void
usage_radio (void)
{
	g_printerr (_("Usage: nmcli radio { COMMAND | help }\n\n"
	              "COMMAND := { all | wifi | wwan }\n\n"
	              "  all | wifi | wwan [ on | off ]\n\n"
	              ));
}

static void
usage_radio_all (void)
{
	g_printerr (_("Usage: nmcli radio all { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [on | off]\n"
	              "\n"
	              "Get status of all radio switches, or turn them on/off.\n\n"));
}

static void
usage_radio_wifi (void)
{
	g_printerr (_("Usage: nmcli radio wifi { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [on | off]\n"
	              "\n"
	              "Get status of Wi-Fi radio switch, or turn it on/off.\n\n"));
}

static void
usage_radio_wwan (void)
{
	g_printerr (_("Usage: nmcli radio wwan { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [on | off]\n"
	              "\n"
	              "Get status of mobile broadband radio switch, or turn it on/off.\n\n"));
}

static void
usage_monitor (void)
{
	g_printerr (_("Usage: nmcli monitor\n"
	              "\n"
	              "Monitor NetworkManager changes.\n"
	              "Prints a line whenever a change occurs in NetworkManager\n\n"));
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

static NmcTermColor
state_to_color (NMState state)
{
	switch (state) {
	case NM_STATE_CONNECTING:
		return NMC_TERM_COLOR_YELLOW;
	case NM_STATE_CONNECTED_LOCAL:
	case NM_STATE_CONNECTED_SITE:
	case NM_STATE_CONNECTED_GLOBAL:
		return NMC_TERM_COLOR_GREEN;
	case NM_STATE_DISCONNECTING:
		return NMC_TERM_COLOR_YELLOW;
	case NM_STATE_ASLEEP:
	case NM_STATE_DISCONNECTED:
		return NMC_TERM_COLOR_RED;
	default:
		return NMC_TERM_COLOR_NORMAL;
	}
}

static const char *
nm_connectivity_to_string (NMConnectivityState connectivity)
{
	switch (connectivity) {
	case NM_CONNECTIVITY_NONE:
		return _("none");
	case NM_CONNECTIVITY_PORTAL:
		return _("portal");
	case NM_CONNECTIVITY_LIMITED:
		return _("limited");
	case NM_CONNECTIVITY_FULL:
		return _("full");
	case NM_CONNECTIVITY_UNKNOWN:
	default:
		return _("unknown");
	}
}

static NmcTermColor
connectivity_to_color (NMConnectivityState connectivity)
{
	switch (connectivity) {
	case NM_CONNECTIVITY_NONE:
		return NMC_TERM_COLOR_RED;
	case NM_CONNECTIVITY_PORTAL:
	case NM_CONNECTIVITY_LIMITED:
		return NMC_TERM_COLOR_YELLOW;
	case NM_CONNECTIVITY_FULL:
		return NMC_TERM_COLOR_GREEN;
	default:
		return NMC_TERM_COLOR_NORMAL;
	}
}

static gboolean
show_nm_status (NmCli *nmc, const char *pretty_header_name, const char *print_flds)
{
	gboolean startup = FALSE;
	NMState state = NM_STATE_UNKNOWN;
	NMConnectivityState connectivity = NM_CONNECTIVITY_UNKNOWN;
	gboolean net_enabled;
	gboolean wireless_hw_enabled, wireless_enabled;
	gboolean wwan_hw_enabled, wwan_enabled;
	GError *error = NULL;
	const char *fields_str;
	const char *fields_all =    print_flds ? print_flds : NMC_FIELDS_NM_STATUS_ALL;
	const char *fields_common = print_flds ? print_flds : NMC_FIELDS_NM_STATUS_COMMON;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else
		fields_str = nmc->required_fields;

	tmpl = nmc_fields_nm_status;
	tmpl_len = sizeof (nmc_fields_nm_status);
	nmc->print_fields.indices = parse_output_fields (fields_str, tmpl, FALSE, NULL, &error);

	if (error) {
		g_string_printf (nmc->return_text, _("Error: only these fields are allowed: %s"), fields_all);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return FALSE;
	}

	state = nm_client_get_state (nmc->client);
	startup = nm_client_get_startup (nmc->client);
	connectivity = nm_client_get_connectivity (nmc->client);
	net_enabled = nm_client_networking_get_enabled (nmc->client);
	wireless_hw_enabled = nm_client_wireless_hardware_get_enabled (nmc->client);
	wireless_enabled = nm_client_wireless_get_enabled (nmc->client);
	wwan_hw_enabled = nm_client_wwan_hardware_get_enabled (nmc->client);
	wwan_enabled = nm_client_wwan_get_enabled (nmc->client);

	nmc->print_fields.header_name = pretty_header_name ? (char *) pretty_header_name : _("NetworkManager status");
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, 0);
	set_val_strc (arr, 0, _("running"));
	set_val_strc (arr, 1, nm_client_get_version (nmc->client));
	set_val_strc (arr, 2, nm_state_to_string (state));
	set_val_strc (arr, 3, startup ? _("starting") : _("started"));
	set_val_strc (arr, 4, nm_connectivity_to_string (connectivity));
	set_val_strc (arr, 5, net_enabled ? _("enabled") : _("disabled"));
	set_val_strc (arr, 6, wireless_hw_enabled ? _("enabled") : _("disabled"));
	set_val_strc (arr, 7, wireless_enabled ? _("enabled") : _("disabled"));
	set_val_strc (arr, 8, wwan_hw_enabled ? _("enabled") : _("disabled"));
	set_val_strc (arr, 9, wwan_enabled ? _("enabled") : _("disabled"));

	/* Set colors */
	arr[2].color = state_to_color (state);
	arr[3].color = startup ? NMC_TERM_COLOR_YELLOW : NMC_TERM_COLOR_GREEN;
	arr[4].color = connectivity_to_color (connectivity);
	arr[5].color = net_enabled ? NMC_TERM_COLOR_GREEN : NMC_TERM_COLOR_RED;
	arr[6].color = wireless_hw_enabled ? NMC_TERM_COLOR_GREEN : NMC_TERM_COLOR_RED;
	arr[7].color = wireless_enabled ? NMC_TERM_COLOR_GREEN : NMC_TERM_COLOR_RED;
	arr[8].color = wwan_hw_enabled ? NMC_TERM_COLOR_GREEN : NMC_TERM_COLOR_RED;
	arr[9].color = wwan_enabled ? NMC_TERM_COLOR_GREEN : NMC_TERM_COLOR_RED;

	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static NMCResultCode
do_general_status (NmCli *nmc, int argc, char **argv)
{
	gs_free_error GError *error = NULL;

        if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error)) {
                g_string_printf (nmc->return_text, _("Error: %s."), error->message);
                return NMC_RESULT_ERROR_USER_INPUT;
	}

	if (nmc->complete)
		return nmc->return_value;

	show_nm_status (nmc, NULL, NULL);
	return nmc->return_value;
}

static const char *
permission_to_string (NMClientPermission perm)
{
	switch (perm) {
	case NM_CLIENT_PERMISSION_ENABLE_DISABLE_NETWORK:
		return NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK;
	case NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIFI:
		return NM_AUTH_PERMISSION_ENABLE_DISABLE_WIFI;
	case NM_CLIENT_PERMISSION_ENABLE_DISABLE_WWAN:
		return NM_AUTH_PERMISSION_ENABLE_DISABLE_WWAN;
	case NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIMAX:
		return NM_AUTH_PERMISSION_ENABLE_DISABLE_WIMAX;
	case NM_CLIENT_PERMISSION_SLEEP_WAKE:
		return NM_AUTH_PERMISSION_SLEEP_WAKE;
	case NM_CLIENT_PERMISSION_NETWORK_CONTROL:
		return NM_AUTH_PERMISSION_NETWORK_CONTROL;
	case NM_CLIENT_PERMISSION_WIFI_SHARE_PROTECTED:
		return NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED;
	case NM_CLIENT_PERMISSION_WIFI_SHARE_OPEN:
		return NM_AUTH_PERMISSION_WIFI_SHARE_OPEN;
	case NM_CLIENT_PERMISSION_SETTINGS_MODIFY_SYSTEM:
		return NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM;
	case NM_CLIENT_PERMISSION_SETTINGS_MODIFY_OWN:
		return NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN;
	case NM_CLIENT_PERMISSION_SETTINGS_MODIFY_HOSTNAME:
		return NM_AUTH_PERMISSION_SETTINGS_MODIFY_HOSTNAME;
	case NM_CLIENT_PERMISSION_SETTINGS_MODIFY_GLOBAL_DNS:
		return NM_AUTH_PERMISSION_SETTINGS_MODIFY_GLOBAL_DNS;
	case NM_CLIENT_PERMISSION_RELOAD:
		return NM_AUTH_PERMISSION_RELOAD;
	case NM_CLIENT_PERMISSION_CHECKPOINT_ROLLBACK:
		return NM_AUTH_PERMISSION_CHECKPOINT_ROLLBACK;
	case NM_CLIENT_PERMISSION_ENABLE_DISABLE_STATISTICS:
		return NM_AUTH_PERMISSION_ENABLE_DISABLE_STATISTICS;
	default:
		return _("unknown");
	}
}

static const char *
permission_result_to_string (NMClientPermissionResult perm_result)
{
	switch (perm_result) {
	case NM_CLIENT_PERMISSION_RESULT_YES:
		return _("yes");
	case NM_CLIENT_PERMISSION_RESULT_NO:
		return _("no");
	case NM_CLIENT_PERMISSION_RESULT_AUTH:
		return _("auth");
	default:
		return _("unknown");
	}
}

static gboolean
timeout_cb (gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;

	g_string_printf (nmc->return_text, _("Error: Timeout %d sec expired."), nmc->timeout);
	nmc->return_value = NMC_RESULT_ERROR_TIMEOUT_EXPIRED;
	quit ();
	return FALSE;
}

static int
print_permissions (void *user_data)
{
	NmCli *nmc = user_data;
	NMClientPermission perm;
	GError *error = NULL;
	const char *fields_str;
	const char *fields_all =    NMC_FIELDS_NM_PERMISSIONS_ALL;
	const char *fields_common = NMC_FIELDS_NM_PERMISSIONS_COMMON;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else
		fields_str = nmc->required_fields;

	tmpl = nmc_fields_nm_permissions;
	tmpl_len = sizeof (nmc_fields_nm_permissions);
	nmc->print_fields.indices = parse_output_fields (fields_str, tmpl, FALSE, NULL, &error);

	if (error) {
		g_string_printf (nmc->return_text, _("Error: 'general permissions': %s"), error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return FALSE;
	}

	nmc->print_fields.header_name = _("NetworkManager permissions");
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);


	for (perm = NM_CLIENT_PERMISSION_NONE + 1; perm <= NM_CLIENT_PERMISSION_LAST; perm++) {
		NMClientPermissionResult perm_result = nm_client_get_permission_result (nmc->client, perm);

		arr = nmc_dup_fields_array (tmpl, tmpl_len, 0);
		set_val_strc (arr, 0, permission_to_string (perm));
		set_val_strc (arr, 1, permission_result_to_string (perm_result));
		g_ptr_array_add (nmc->output_data, arr);
	}
	print_data (nmc);  /* Print all data */

	quit ();
	return G_SOURCE_REMOVE;
}

static gboolean
got_permissions (NmCli *nmc)
{
	NMClientPermission perm;

	/* The server returns all the permissions at once, so if at least one is there
	 * we already received the reply. */
	for (perm = NM_CLIENT_PERMISSION_NONE + 1; perm <= NM_CLIENT_PERMISSION_LAST; perm++) {
		if (nm_client_get_permission_result (nmc->client, perm) != NM_CLIENT_PERMISSION_RESULT_UNKNOWN)
			return TRUE;
	}

	return FALSE;
}

static void
permission_changed (NMClient *client,
                    NMClientPermission permission,
                    NMClientPermissionResult result,
                    NmCli *nmc)
{
	if (got_permissions (nmc)) {
		/* Defer the printing, so that we have a chance to process the other
		 * permission-changed signals. */
		g_idle_remove_by_data (nmc);
		g_idle_add (print_permissions, nmc);
	}
}

static gboolean
show_nm_permissions (NmCli *nmc)
{
	/* The permissions are available now, just print them. */
	if (got_permissions (nmc)) {
		print_permissions (nmc);
		return TRUE;
	}

	/* The client didn't get the permissions reply yet. Subscribe to changes. */
	g_signal_connect (nmc->client, NM_CLIENT_PERMISSION_CHANGED,
                          G_CALLBACK (permission_changed), nmc);

	if (nmc->timeout == -1)
		nmc->timeout = 10;
	g_timeout_add_seconds (nmc->timeout, timeout_cb, nmc);

	nmc->should_wait++;
	return TRUE;
}

static NMCResultCode
do_general_permissions (NmCli *nmc, int argc, char **argv)
{
	gs_free_error GError *error = NULL;

        if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error)) {
                g_string_printf (nmc->return_text, _("Error: %s."), error->message);
                return NMC_RESULT_ERROR_USER_INPUT;
	}

	if (nmc->complete)
		return nmc->return_value;

	show_nm_permissions (nmc);
	return nmc->return_value;
}

static gboolean
show_general_logging (NmCli *nmc)
{
	char *level = NULL;
	char *domains = NULL;
	GError *error = NULL;
	const char *fields_str;
	const char *fields_all =    NMC_FIELDS_NM_LOGGING_ALL;
	const char *fields_common = NMC_FIELDS_NM_LOGGING_COMMON;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else
		fields_str = nmc->required_fields;

	tmpl = nmc_fields_nm_logging;
	tmpl_len = sizeof (nmc_fields_nm_logging);
	nmc->print_fields.indices = parse_output_fields (fields_str, tmpl, FALSE, NULL, &error);

	if (error) {
		g_string_printf (nmc->return_text, _("Error: 'general logging': %s"), error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return FALSE;
	}

	nm_client_get_logging (nmc->client, &level, &domains, &error);
	if (error) {
		g_string_printf (nmc->return_text, _("Error: %s."), error->message);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		g_error_free (error);
		return FALSE;
	}

	nmc->print_fields.header_name = _("NetworkManager logging");
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, 0);
	set_val_str (arr, 0, level);
	set_val_str (arr, 1, domains);
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static NMCResultCode
do_general_logging (NmCli *nmc, int argc, char **argv)
{
	gs_free_error GError *error = NULL;

	if (argc == 0) {
		if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error)) {
			g_string_printf (nmc->return_text, _("Error: %s."), error->message);
			g_error_free (error);
			return NMC_RESULT_ERROR_USER_INPUT;
		}

		if (nmc->complete)
			return nmc->return_value;

		show_general_logging (nmc);
	} else {
		/* arguments provided -> set logging level and domains */
		const char *level = NULL;
		const char *domains = NULL;
		nmc_arg_t exp_args[] = { {"level",   TRUE, &level,   TRUE},
		                         {"domains", TRUE, &domains, TRUE},
		                         {NULL} };

		/* TODO: nmc_parse_args needs completion */
		if (nmc->complete)
			return nmc->return_value;

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, &error)) {
			g_string_assign (nmc->return_text, error->message);
			return error->code;
		}

		nm_client_set_logging (nmc->client, level, domains, &error);
		if (error) {
			g_string_printf (nmc->return_text, _("Error: failed to set logging: %s"),
			                 nmc_error_get_simple_message (error));
			return NMC_RESULT_ERROR_UNKNOWN;
		}
	}

	return nmc->return_value;
}

static void
save_hostname_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;
	GError *error = NULL;

	nm_client_save_hostname_finish (NM_CLIENT (object), result, &error);
	if (error) {
		g_string_printf (nmc->return_text, _("Error: failed to set hostname: %s"),
		                 error->message);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		g_error_free (error);
	}
	quit ();
}

static NMCResultCode
do_general_hostname (NmCli *nmc, int argc, char **argv)
{
	if (nmc->complete)
		return nmc->return_value;

	if (argc == 0) {
		/* no arguments -> get hostname */
		char *hostname = NULL;

		g_object_get (nmc->client, NM_CLIENT_HOSTNAME, &hostname, NULL);
		if (hostname)
			g_print ("%s\n", hostname);
		g_free (hostname);
	} else {
		/* hostname provided -> set it */
		const char *hostname = *argv;

		if (next_arg (&argc, &argv) == 0)
			g_print ("Warning: ignoring extra garbage after '%s' hostname\n", hostname);

		nmc->should_wait++;
		nm_client_save_hostname_async (nmc->client, hostname, NULL, save_hostname_cb, nmc);
	}

	return nmc->return_value;

}

static const NMCCommand general_cmds[] = {
	{ "status",       do_general_status,       usage_general_status,       TRUE,   TRUE },
	{ "hostname",     do_general_hostname,     usage_general_hostname,     TRUE,   TRUE },
	{ "permissions",  do_general_permissions,  usage_general_permissions,  TRUE,   TRUE },
	{ "logging",      do_general_logging,      usage_general_logging,      TRUE,   TRUE },
	{ NULL,           do_general_status,       usage_general,              TRUE,   TRUE },
};

/*
 * Entry point function for general operations 'nmcli general'
 */
NMCResultCode
do_general (NmCli *nmc, int argc, char **argv)
{
	/* Register polkit agent */
	nmc_start_polkit_agent_start_try (nmc);

	nmc_do_cmd (nmc, general_cmds, *argv, argc, argv);

	return nmc->return_value;
}

static gboolean
nmc_switch_show (NmCli *nmc, const char *switch_name, const char *header)
{
	g_return_val_if_fail (nmc != NULL, FALSE);
	g_return_val_if_fail (switch_name != NULL, FALSE);

	if (nmc->required_fields && strcasecmp (nmc->required_fields, switch_name) != 0) {
		g_string_printf (nmc->return_text, _("Error: '--fields' value '%s' is not valid here (allowed field: %s)"),
		                 nmc->required_fields, switch_name);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return FALSE;
	}
	if (nmc->print_output == NMC_PRINT_NORMAL)
		nmc->print_output = NMC_PRINT_TERSE;

	if (!nmc->required_fields)
		nmc->required_fields = g_strdup (switch_name);
	return show_nm_status (nmc, header, NULL);
}

static gboolean
nmc_switch_parse_on_off (NmCli *nmc, const char *arg1, const char *arg2, gboolean *res)
{
	g_return_val_if_fail (nmc != NULL, FALSE);
	g_return_val_if_fail (arg1 && arg2, FALSE);
	g_return_val_if_fail (res != NULL, FALSE);

	if (!strcmp (arg2, "on"))
		*res = TRUE;
	else if (!strcmp (arg2, "off"))
		*res = FALSE;
	else {
		g_string_printf (nmc->return_text, _("Error: invalid '%s' argument: '%s' (use on/off)."), arg1, arg2);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return FALSE;
	}

	return TRUE;
}

static NMCResultCode
do_networking_on_off (NmCli *nmc, int argc, char **argv, gboolean enable)
{
	if (nmc->complete)
		return nmc->return_value;

	/* Register polkit agent */
	nmc_start_polkit_agent_start_try (nmc);

	nm_client_networking_set_enabled (nmc->client, enable, NULL);

	return nmc->return_value;
}

static NMCResultCode
do_networking_on (NmCli *nmc, int argc, char **argv)
{
	return do_networking_on_off (nmc, argc, argv, TRUE);
}

static NMCResultCode
do_networking_off (NmCli *nmc, int argc, char **argv)
{
	return do_networking_on_off (nmc, argc, argv, FALSE);
}

static NMCResultCode
do_networking_connectivity (NmCli *nmc, int argc, char **argv)
{
	if (nmc->complete) {
		if (argc == 1)
			nmc_complete_strings (*argv, "check", NULL);
		return nmc->return_value;
	}

	if (!argc) {
		/* no arguments -> get current state */
		nmc_switch_show (nmc, NMC_FIELDS_NM_CONNECTIVITY, _("Connectivity"));
	} else if (matches (*argv, "check") == 0) {
		gs_free_error GError *error = NULL;

		/* Register polkit agent */
		nmc_start_polkit_agent_start_try (nmc);

		nm_client_check_connectivity (nmc->client, NULL, &error);
		if (error) {
			g_string_printf (nmc->return_text, _("Error: %s."), error->message);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		} else
			nmc_switch_show (nmc, NMC_FIELDS_NM_CONNECTIVITY, _("Connectivity"));
	} else {
		usage_networking ();
		g_string_printf (nmc->return_text, _("Error: 'networking' command '%s' is not valid."), *argv);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
	}

	return nmc->return_value;
}

static NMCResultCode
do_networking_show (NmCli *nmc, int argc, char **argv)
{
	if (nmc->complete)
		return nmc->return_value;

	nmc_switch_show (nmc, NMC_FIELDS_NM_NETWORKING, _("Networking"));

	return nmc->return_value;
}

static const NMCCommand networking_cmds[] = {
	{ "on",           do_networking_on,           usage_networking_on,           TRUE,   TRUE },
	{ "off",          do_networking_off,          usage_networking_off,          TRUE,   TRUE },
	{ "connectivity", do_networking_connectivity, usage_networking_connectivity, TRUE,   TRUE },
	{ NULL,           do_networking_show,         usage_networking,              TRUE,   TRUE },
};

/*
 * Entry point function for networking commands 'nmcli networking'
 */
NMCResultCode
do_networking (NmCli *nmc, int argc, char **argv)
{
	nmc_do_cmd (nmc, networking_cmds, *argv, argc, argv);

	return nmc->return_value;
}

static NMCResultCode
do_radio_all (NmCli *nmc, int argc, char **argv)
{
	gboolean enable_flag;
	gs_free_error GError *error = NULL;

	if (argc == 0) {
		if (nmc->complete)
			return nmc->return_value;

		/* no argument, show all radio switches */
		if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error)) {
			g_string_printf (nmc->return_text, _("Error: %s."), error->message);
			return NMC_RESULT_ERROR_USER_INPUT;
		}
		show_nm_status (nmc, _("Radio switches"), NMC_FIELDS_NM_STATUS_RADIO);
	} else {
		if (nmc->complete) {
			if (argc == 1)
				nmc_complete_bool (*argv);
			return nmc->return_value;
		}

		if (!nmc_switch_parse_on_off (nmc, *(argv-1), *argv, &enable_flag))
			return nmc->return_value;

		nm_client_wireless_set_enabled (nmc->client, enable_flag);
		nm_client_wimax_set_enabled (nmc->client, enable_flag);
		nm_client_wwan_set_enabled (nmc->client, enable_flag);
	}

	return nmc->return_value;
}

static NMCResultCode
do_radio_wifi (NmCli *nmc, int argc, char **argv)
{
	gboolean enable_flag;

	if (argc == 0) {
		if (nmc->complete)
			return nmc->return_value;

		/* no argument, show current WiFi state */
		nmc_switch_show (nmc, NMC_FIELDS_NM_WIFI, _("Wi-Fi radio switch"));
	} else {
		if (nmc->complete) {
			if (argc == 1)
				nmc_complete_bool (*argv);
			return nmc->return_value;
		}
		if (!nmc_switch_parse_on_off (nmc, *(argv-1), *argv, &enable_flag))
			return nmc->return_value;

		nm_client_wireless_set_enabled (nmc->client, enable_flag);
	}

	return nmc->return_value;
}

static NMCResultCode
do_radio_wwan (NmCli *nmc, int argc, char **argv)
{
	gboolean enable_flag;

	if (argc == 0) {
		if (nmc->complete)
			return nmc->return_value;

		/* no argument, show current WWAN (mobile broadband) state */
		nmc_switch_show (nmc, NMC_FIELDS_NM_WWAN, _("WWAN radio switch"));
	} else {
		if (nmc->complete) {
			if (argc == 1)
				nmc_complete_bool (*argv);
			return nmc->return_value;
		}
		if (!nmc_switch_parse_on_off (nmc, *(argv-1), *argv, &enable_flag))
			return nmc->return_value;

		nm_client_wwan_set_enabled (nmc->client, enable_flag);
	}

	return nmc->return_value;
}

static const NMCCommand radio_cmds[] = {
	{ "all",   do_radio_all,   usage_radio_all,   TRUE,   TRUE },
	{ "wifi",  do_radio_wifi,  usage_radio_wifi,  TRUE,   TRUE },
	{ "wwan",  do_radio_wwan,  usage_radio_wwan,  TRUE,   TRUE },
	{ NULL,    do_radio_all,   usage_radio,       TRUE,   TRUE },
};

/*
 * Entry point function for radio switch commands 'nmcli radio'
 */
NMCResultCode
do_radio (NmCli *nmc, int argc, char **argv)
{
	/* Register polkit agent */
	nmc_start_polkit_agent_start_try (nmc);

	nmc_do_cmd (nmc, radio_cmds, *argv, argc, argv);

	return nmc->return_value;
}

static void
networkmanager_running (NMClient *client, GParamSpec *param, NmCli *nmc)
{
	gboolean running;
	char *str;

	running = nm_client_get_nm_running (client);
	str = nmc_colorize (nmc,
	                    running ? NMC_TERM_COLOR_GREEN : NMC_TERM_COLOR_RED,
	                    NMC_TERM_FORMAT_NORMAL,
	                    running ? _("NetworkManager has started") : _("NetworkManager has stopped"));
	g_print ("%s\n", str);
	g_free (str);
}

static void
client_hostname (NMClient *client, GParamSpec *param, NmCli *nmc)
{
	const char *hostname;

	g_object_get (client, NM_CLIENT_HOSTNAME, &hostname, NULL);
	g_print (_("Hostname set to '%s'\n"), hostname);
}

static void
client_primary_connection (NMClient *client, GParamSpec *param, NmCli *nmc)
{
	NMActiveConnection *primary;
	const char *id;

	primary = nm_client_get_primary_connection (client);
	if (primary) {
		id = nm_active_connection_get_id (primary);
		if (!id)
			id = nm_active_connection_get_uuid (primary);

		g_print (_("'%s' is now the primary connection\n"), id);
	} else {
		g_print (_("There's no primary connection\n"));
	}
}

static void
client_connectivity (NMClient *client, GParamSpec *param, NmCli *nmc)
{
	NMConnectivityState connectivity;
	char *str;

	g_object_get (client, NM_CLIENT_CONNECTIVITY, &connectivity, NULL);
	str = nmc_colorize (nmc, connectivity_to_color (connectivity), NMC_TERM_FORMAT_NORMAL,
	                    _("Connectivity is now '%s'\n"), nm_connectivity_to_string (connectivity));
	g_print ("%s", str);
	g_free (str);
}

static void
client_state (NMClient *client, GParamSpec *param, NmCli *nmc)
{
	NMState state;
	char *str;

	g_object_get (client, NM_CLIENT_STATE, &state, NULL);
	str = nmc_colorize (nmc, state_to_color (state), NMC_TERM_FORMAT_NORMAL,
	                    _("Networkmanager is now in the '%s' state\n"),
	                    nm_state_to_string (state));
	g_print ("%s", str);
	g_free (str);
}


static void
device_overview (NmCli *nmc, NMDevice *device)
{
	GString *outbuf = g_string_sized_new (80);
	char *tmp;
	const GPtrArray *activatable;

	activatable = nm_device_get_available_connections (device);

	g_string_append_printf (outbuf, "%s", nm_device_get_type_description (device));

	if (nm_device_get_state (device) == NM_DEVICE_STATE_DISCONNECTED) {
		if (activatable) {
			if (activatable->len == 1)
				g_print ("\t%d %s\n", activatable->len, _("connection available"));
			else if (activatable->len > 1)
				g_print ("\t%d %s\n", activatable->len, _("connections available"));
		}
	}

	if (   nm_device_get_driver (device)
	    && strcmp (nm_device_get_driver (device), "")
	    && strcmp (nm_device_get_driver (device), nm_device_get_type_description (device))) {
		g_string_append_printf (outbuf, " (%s)", nm_device_get_driver (device));
	}

	g_string_append_printf (outbuf, ", ");

	if (   nm_device_get_hw_address (device)
	    && strcmp (nm_device_get_hw_address (device), "")) {
		g_string_append_printf (outbuf, "%s, ", nm_device_get_hw_address (device));
	}

	if (!nm_device_get_autoconnect (device))
		g_string_append_printf (outbuf, "%s, ", _("autoconnect"));
	if (nm_device_get_firmware_missing (device)) {
		tmp = nmc_colorize (nmc, NMC_TERM_COLOR_RED, NMC_TERM_FORMAT_NORMAL, _("fw missing"));
		g_string_append_printf (outbuf, "%s, ", tmp);
		g_free (tmp);
	}
	if (nm_device_get_nm_plugin_missing (device)) {
		tmp = nmc_colorize (nmc, NMC_TERM_COLOR_RED, NMC_TERM_FORMAT_NORMAL, _("plugin missing"));
		g_string_append_printf (outbuf, "%s, ", tmp);
		g_free (tmp);
	}
	if (nm_device_is_software (device))
		g_string_append_printf (outbuf, "%s, ", _("sw"));
	else
		g_string_append_printf (outbuf, "%s, ", _("hw"));

	if (   nm_device_get_ip_iface (device)
	    && g_strcmp0 (nm_device_get_ip_iface (device), nm_device_get_iface (device))
	    && g_strcmp0 (nm_device_get_ip_iface (device), ""))
		g_string_append_printf (outbuf, "%s %s,", _("iface"), nm_device_get_ip_iface (device));

	if (nm_device_get_physical_port_id (device))
		g_string_append_printf (outbuf, "%s %s, ", _("port"), nm_device_get_physical_port_id (device));

	if (nm_device_get_mtu (device))
		g_string_append_printf (outbuf, "%s %d, ", _("mtu"), nm_device_get_mtu (device));

	if (outbuf->len >= 2) {
		g_string_truncate (outbuf, outbuf->len - 2);
		g_print ("\t%s\n", outbuf->str);
	}

	g_string_free (outbuf, TRUE);
}

static void
ac_overview (NmCli *nmc, NMActiveConnection *ac)
{
	GString *outbuf = g_string_sized_new (80);
	NMIPConfig *ip;

	if (nm_active_connection_get_master (ac)) {
		g_string_append_printf (outbuf, "%s %s,", _("master"),
		                        nm_device_get_iface (nm_active_connection_get_master (ac)));
	}
	if (nm_active_connection_get_vpn (ac))
		g_string_append_printf (outbuf, "%s, ", _("VPN"));
	if (nm_active_connection_get_default (ac))
		g_string_append_printf (outbuf, "%s, ", _("ip4 default"));
	if (nm_active_connection_get_default6 (ac))
		g_string_append_printf (outbuf, "%s, ", _("ip6 default"));
	if (outbuf->len >= 2) {
		g_string_truncate (outbuf, outbuf->len - 2);
		g_print ("\t%s\n", outbuf->str);
	}

	ip = nm_active_connection_get_ip4_config (ac);
	if (ip) {
		const GPtrArray *p;
		int i;

		p = nm_ip_config_get_addresses (ip);
		for (i = 0; i < p->len; i++) {
			NMIPAddress *a = p->pdata[i];
			g_print ("\tinet4 %s/%d\n", nm_ip_address_get_address (a),
			                            nm_ip_address_get_prefix (a));
		}

		p = nm_ip_config_get_routes (ip);
		for (i = 0; i < p->len; i++) {
			NMIPRoute *a = p->pdata[i];
			g_print ("\troute4 %s/%d\n", nm_ip_route_get_dest (a),
			                            nm_ip_route_get_prefix (a));
		}
	}

	ip = nm_active_connection_get_ip6_config (ac);
	if (ip) {
		const GPtrArray *p;
		int i;

		p = nm_ip_config_get_addresses (ip);
		for (i = 0; i < p->len; i++) {
			NMIPAddress *a = p->pdata[i];
			g_print ("\tinet6 %s/%d\n", nm_ip_address_get_address (a),
			                            nm_ip_address_get_prefix (a));
		}

		p = nm_ip_config_get_routes (ip);
		for (i = 0; i < p->len; i++) {
			NMIPRoute *a = p->pdata[i];
			g_print ("\troute6 %s/%d\n", nm_ip_route_get_dest (a),
			                            nm_ip_route_get_prefix (a));
		}
	}

	g_string_free (outbuf, TRUE);
}

/*
 * Entry point function for 'nmcli' without arguments.
 */
NMCResultCode
do_overview (NmCli *nmc, int argc, char **argv)
{
	NMDevice **devices;
	const GPtrArray *p;
	NMActiveConnection *ac;
	NmcTermColor color;
	NMDnsEntry *dns;
	char *tmp;
	int i;

	/* Register polkit agent */
	nmc_start_polkit_agent_start_try (nmc);

	/* The VPN connections don't have devices (yet?). */
	p = nm_client_get_active_connections (nmc->client);
	for (i = 0; i < p->len; i++) {
		NMActiveConnectionState state;

		ac = p->pdata[i];

		if (!nm_active_connection_get_vpn (ac))
			continue;

		state = nm_active_connection_get_state (ac);
		nmc_active_connection_state_to_color (state, &color);
		tmp = nmc_colorize (nmc, color, NMC_TERM_FORMAT_NORMAL, _("%s VPN connection"),
		                    nm_active_connection_get_id (ac));
		g_print ("%s\n", tmp);
		g_free (tmp);

		ac_overview (nmc, ac);
		g_print ("\n");
	}

	devices = nmc_get_devices_sorted (nmc->client);
	for (i = 0; devices[i]; i++) {
		NmcTermFormat color_fmt;
		NMDeviceState state;

		ac = nm_device_get_active_connection (devices[i]);

		state = nm_device_get_state (devices[i]);
		nmc_device_state_to_color (state, &color, &color_fmt);
		tmp = nmc_colorize (nmc, color, color_fmt, "%s: %s%s%s",
		                    nm_device_get_iface (devices[i]),
		                    nmc_device_state_to_string (state),
		                    ac ? " to " : "",
		                    ac ? nm_active_connection_get_id (ac) : "");
		g_print ("%s\n", tmp);
		g_free (tmp);

		if (nm_device_get_description (devices[i]) && strcmp (nm_device_get_description (devices[i]), ""))
			g_print ("\t\"%s\"\n", nm_device_get_description (devices[i]));


		device_overview (nmc, devices[i]);
		if (ac)
			ac_overview (nmc, ac);
		g_print ("\n");
	}
	g_free (devices);

	p = nm_client_get_dns_configuration (nmc->client);
	for (i = 0; p && i < p->len; i++) {
		const char * const *strv;

		dns = p->pdata[i];
		strv = nm_dns_entry_get_nameservers (dns);
		if (!strv || !strv[0]) {
			/* Invalid entry */
			continue;
		}

		if (i == 0)
			g_print ("DNS configuration:\n");

		tmp = g_strjoinv (" ", (char **) strv);
		g_print ("\tservers: %s\n", tmp);
		g_free (tmp);

		strv = nm_dns_entry_get_domains (dns);
		if (strv && strv[0]) {
			tmp = g_strjoinv (" ", (char **) strv);
			g_print ("\tdomains: %s\n", tmp);
			g_free (tmp);
		}

		if (nm_dns_entry_get_interface (dns))
			g_print ("\tinterface: %s\n", nm_dns_entry_get_interface (dns));

		if (nm_dns_entry_get_vpn (dns))
			g_print ("\ttype: vpn\n");
		g_print ("\n");
	}

	g_print (_("Use \"nmcli device show\" to get complete information about known devices and\n"
	           "\"nmcli connection show\" to get an overview on active connection profiles.\n"
	           "\n"
	           "Consult nmcli(1) and nmcli-examples(5) manual pages for complete usage details.\n"));

	return NMC_RESULT_SUCCESS;
}

/*
 * Entry point function for 'nmcli monitor'
 */
NMCResultCode
do_monitor (NmCli *nmc, int argc, char **argv)
{
	if (nmc->complete)
		return nmc->return_value;

	if (argc > 0) {
		if (!nmc_arg_is_help (*argv)) {
			g_string_printf (nmc->return_text, _("Error: 'monitor' command '%s' is not valid."), *argv);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		}

		usage_monitor ();
		return nmc->return_value;
	}

	if (!nm_client_get_nm_running (nmc->client)) {
		char *str;

		str = nmc_colorize (nmc, NMC_TERM_COLOR_RED, NMC_TERM_FORMAT_NORMAL,
		                    _("Networkmanager is not running (waiting for it)\n"));
		g_print ("%s", str);
		g_free (str);
	}

	g_signal_connect (nmc->client, "notify::" NM_CLIENT_NM_RUNNING,
	                  G_CALLBACK (networkmanager_running), nmc);
	g_signal_connect (nmc->client, "notify::" NM_CLIENT_HOSTNAME,
	                  G_CALLBACK (client_hostname), nmc);
	g_signal_connect (nmc->client, "notify::" NM_CLIENT_PRIMARY_CONNECTION,
	                  G_CALLBACK (client_primary_connection), nmc);
	g_signal_connect (nmc->client, "notify::" NM_CLIENT_CONNECTIVITY,
	                  G_CALLBACK (client_connectivity), nmc);
	g_signal_connect (nmc->client, "notify::" NM_CLIENT_STATE,
	                  G_CALLBACK (client_state), nmc);

	nmc->should_wait++;

	monitor_devices (nmc);
	monitor_connections (nmc);

	return NMC_RESULT_SUCCESS;
}
