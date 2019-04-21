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
 * Copyright 2010 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "general.h"

#include <stdlib.h>

#include "nm-libnm-core-intern/nm-common-macros.h"

#include "nm-client-utils.h"

#include "polkit-agent.h"
#include "utils.h"
#include "common.h"
#include "common.h"
#include "devices.h"
#include "connections.h"

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (nm_state_to_string, NMState,
	NM_UTILS_LOOKUP_DEFAULT (N_("unknown")),
	NM_UTILS_LOOKUP_ITEM (NM_STATE_ASLEEP,           N_("asleep")),
	NM_UTILS_LOOKUP_ITEM (NM_STATE_CONNECTING,       N_("connecting")),
	NM_UTILS_LOOKUP_ITEM (NM_STATE_CONNECTED_LOCAL,  N_("connected (local only)")),
	NM_UTILS_LOOKUP_ITEM (NM_STATE_CONNECTED_SITE,   N_("connected (site only)")),
	NM_UTILS_LOOKUP_ITEM (NM_STATE_CONNECTED_GLOBAL, N_("connected")),
	NM_UTILS_LOOKUP_ITEM (NM_STATE_DISCONNECTING,    N_("disconnecting")),
	NM_UTILS_LOOKUP_ITEM (NM_STATE_DISCONNECTED,     N_("disconnected")),
	NM_UTILS_LOOKUP_ITEM_IGNORE (NM_STATE_UNKNOWN),
);

static NMMetaColor
state_to_color (NMState state)
{
	switch (state) {
	case NM_STATE_CONNECTING:
		return NM_META_COLOR_STATE_CONNECTING;
	case NM_STATE_CONNECTED_LOCAL:
		return NM_META_COLOR_STATE_CONNECTED_LOCAL;
	case NM_STATE_CONNECTED_SITE:
		return NM_META_COLOR_STATE_CONNECTED_SITE;
	case NM_STATE_CONNECTED_GLOBAL:
		return NM_META_COLOR_STATE_CONNECTED_GLOBAL;
	case NM_STATE_DISCONNECTING:
		return NM_META_COLOR_STATE_DISCONNECTING;
	case NM_STATE_ASLEEP:
		return NM_META_COLOR_STATE_ASLEEP;
	case NM_STATE_DISCONNECTED:
		return NM_META_COLOR_STATE_DISCONNECTED;
	default:
		return NM_META_COLOR_STATE_UNKNOWN;
	}
}

static NMMetaColor
connectivity_to_color (NMConnectivityState connectivity)
{
	switch (connectivity) {
	case NM_CONNECTIVITY_NONE:
		return NM_META_COLOR_CONNECTIVITY_NONE;
	case NM_CONNECTIVITY_PORTAL:
		return NM_META_COLOR_CONNECTIVITY_PORTAL;
	case NM_CONNECTIVITY_LIMITED:
		return NM_META_COLOR_CONNECTIVITY_LIMITED;
	case NM_CONNECTIVITY_FULL:
		return NM_META_COLOR_CONNECTIVITY_FULL;
	default:
		return NM_META_COLOR_CONNECTIVITY_UNKNOWN;
	}
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
	case NM_CLIENT_PERMISSION_ENABLE_DISABLE_CONNECTIVITY_CHECK:
		return NM_AUTH_PERMISSION_ENABLE_DISABLE_CONNECTIVITY_CHECK;
	case NM_CLIENT_PERMISSION_WIFI_SCAN:
		return NM_AUTH_PERMISSION_WIFI_SCAN;
	default:
		return _("unknown");
	}
}

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (permission_result_to_string, NMClientPermissionResult,
	NM_UTILS_LOOKUP_DEFAULT (N_("unknown")),
	NM_UTILS_LOOKUP_ITEM (NM_CLIENT_PERMISSION_RESULT_YES,  N_("yes")),
	NM_UTILS_LOOKUP_ITEM (NM_CLIENT_PERMISSION_RESULT_NO,   N_("no")),
	NM_UTILS_LOOKUP_ITEM (NM_CLIENT_PERMISSION_RESULT_AUTH, N_("auth")),
	NM_UTILS_LOOKUP_ITEM_IGNORE (NM_CLIENT_PERMISSION_RESULT_UNKNOWN),
);

_NM_UTILS_LOOKUP_DEFINE (static, permission_result_to_color, NMClientPermissionResult, NMMetaColor,
	NM_UTILS_LOOKUP_DEFAULT (NM_META_COLOR_PERMISSION_UNKNOWN),
	NM_UTILS_LOOKUP_ITEM (NM_CLIENT_PERMISSION_RESULT_YES,  NM_META_COLOR_PERMISSION_YES),
	NM_UTILS_LOOKUP_ITEM (NM_CLIENT_PERMISSION_RESULT_NO,   NM_META_COLOR_PERMISSION_NO),
	NM_UTILS_LOOKUP_ITEM (NM_CLIENT_PERMISSION_RESULT_AUTH, NM_META_COLOR_PERMISSION_AUTH),
	NM_UTILS_LOOKUP_ITEM_IGNORE (NM_CLIENT_PERMISSION_RESULT_UNKNOWN),
);

/*****************************************************************************/

static const NmcMetaGenericInfo *const metagen_general_status[];

static gconstpointer
_metagen_general_status_get_fcn (NMC_META_GENERIC_INFO_GET_FCN_ARGS)
{
	NmCli *nmc = target;
	const char *value;
	gboolean v_bool;
	NMState state;
	NMConnectivityState connectivity;

	switch (info->info_type) {
	case NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_RUNNING:
		NMC_HANDLE_COLOR (NM_META_COLOR_NONE);
		value = N_("running");
		goto translate_and_out;
	case NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_VERSION:
		NMC_HANDLE_COLOR (NM_META_COLOR_NONE);
		value = nm_client_get_version (nmc->client);
		goto clone_and_out;
	case NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_STATE:
		state = nm_client_get_state (nmc->client);
		NMC_HANDLE_COLOR (state_to_color (state));
		value = nm_state_to_string (state);
		goto translate_and_out;
	case NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_STARTUP:
		v_bool = nm_client_get_startup (nmc->client);
		NMC_HANDLE_COLOR (v_bool ? NM_META_COLOR_MANAGER_STARTING : NM_META_COLOR_MANAGER_RUNNING);
		value = v_bool ? N_("starting") : N_("started");
		goto translate_and_out;
	case NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_CONNECTIVITY:
		connectivity = nm_client_get_connectivity (nmc->client);
		NMC_HANDLE_COLOR (connectivity_to_color (connectivity));
		value = nm_connectivity_to_string (connectivity);
		goto translate_and_out;
	case NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_NETWORKING:
		v_bool = nm_client_networking_get_enabled (nmc->client);
		goto enabled_out;
	case NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WIFI_HW:
		v_bool = nm_client_wireless_hardware_get_enabled (nmc->client);
		goto enabled_out;
	case NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WIFI:
		v_bool = nm_client_wireless_get_enabled (nmc->client);
		goto enabled_out;
	case NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WWAN_HW:
		v_bool = nm_client_wwan_hardware_get_enabled (nmc->client);
		goto enabled_out;
	case NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WWAN:
		v_bool = nm_client_wwan_get_enabled (nmc->client);
		goto enabled_out;
	case NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WIMAX_HW:
	case NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WIMAX:
		/* deprecated fields. Don't return anything. */
		return NULL;
	default:
		break;
	}

	g_return_val_if_reached (NULL);

enabled_out:
	NMC_HANDLE_COLOR (v_bool ? NM_META_COLOR_ENABLED : NM_META_COLOR_DISABLED);
	value = v_bool ? N_("enabled") : N_("disabled");
	goto translate_and_out;

clone_and_out:
	return (*out_to_free = g_strdup (value));

translate_and_out:
	if (get_type == NM_META_ACCESSOR_GET_TYPE_PRETTY)
		return _(value);
	return value;
}

static const NmcMetaGenericInfo *const metagen_general_status[_NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_NUM + 1] = {
#define _METAGEN_GENERAL_STATUS(type, name) \
	[type] = NMC_META_GENERIC(name, .info_type = type, .get_fcn = _metagen_general_status_get_fcn)
	_METAGEN_GENERAL_STATUS (NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_RUNNING,       "RUNNING"),
	_METAGEN_GENERAL_STATUS (NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_VERSION,       "VERSION"),
	_METAGEN_GENERAL_STATUS (NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_STATE,         "STATE"),
	_METAGEN_GENERAL_STATUS (NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_STARTUP,       "STARTUP"),
	_METAGEN_GENERAL_STATUS (NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_CONNECTIVITY,  "CONNECTIVITY"),
	_METAGEN_GENERAL_STATUS (NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_NETWORKING,    "NETWORKING"),
	_METAGEN_GENERAL_STATUS (NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WIFI_HW,       "WIFI-HW"),
	_METAGEN_GENERAL_STATUS (NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WIFI,          "WIFI"),
	_METAGEN_GENERAL_STATUS (NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WWAN_HW,       "WWAN-HW"),
	_METAGEN_GENERAL_STATUS (NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WWAN,          "WWAN"),
	_METAGEN_GENERAL_STATUS (NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WIMAX_HW,      "WIMAX-HW"),
	_METAGEN_GENERAL_STATUS (NMC_GENERIC_INFO_TYPE_GENERAL_STATUS_WIMAX,         "WIMAX"),
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

/*****************************************************************************/

static gconstpointer
_metagen_general_permissions_get_fcn (NMC_META_GENERIC_INFO_GET_FCN_ARGS)
{
	NMClientPermission perm = GPOINTER_TO_UINT (target);
	NmCli *nmc = environment_user_data;
	NMClientPermissionResult perm_result;
	const char *s;

	switch (info->info_type) {
	case NMC_GENERIC_INFO_TYPE_GENERAL_PERMISSIONS_PERMISSION:
		NMC_HANDLE_COLOR (NM_META_COLOR_NONE);
		return permission_to_string (perm);
	case NMC_GENERIC_INFO_TYPE_GENERAL_PERMISSIONS_VALUE:
		perm_result = nm_client_get_permission_result (nmc->client, perm);
		NMC_HANDLE_COLOR (permission_result_to_color (perm_result));
		s = permission_result_to_string (perm_result);
		if (get_type == NM_META_ACCESSOR_GET_TYPE_PRETTY)
			return _(s);
		return s;
	default:
		break;
	}

	g_return_val_if_reached (NULL);
}

static const NmcMetaGenericInfo *const metagen_general_permissions[_NMC_GENERIC_INFO_TYPE_GENERAL_PERMISSIONS_NUM + 1] = {
#define _METAGEN_GENERAL_PERMISSIONS(type, name) \
	[type] = NMC_META_GENERIC(name, .info_type = type, .get_fcn = _metagen_general_permissions_get_fcn)
	_METAGEN_GENERAL_PERMISSIONS (NMC_GENERIC_INFO_TYPE_GENERAL_PERMISSIONS_PERMISSION,  "PERMISSION"),
	_METAGEN_GENERAL_PERMISSIONS (NMC_GENERIC_INFO_TYPE_GENERAL_PERMISSIONS_VALUE,       "VALUE"),
};

/*****************************************************************************/

typedef struct {
	bool initialized;
	char **level;
	char **domains;
} GetGeneralLoggingData;

static gconstpointer
_metagen_general_logging_get_fcn (NMC_META_GENERIC_INFO_GET_FCN_ARGS)
{
	NmCli *nmc = environment_user_data;
	GetGeneralLoggingData *d = target;

	nm_assert (info->info_type < _NMC_GENERIC_INFO_TYPE_GENERAL_LOGGING_NUM);

	NMC_HANDLE_COLOR (NM_META_COLOR_NONE);

	if (!d->initialized) {
		d->initialized = TRUE;
		if (!nm_client_get_logging (nmc->client,
		                            d->level,
		                            d->domains,
		                            NULL))
			return NULL;
	}

	if (info->info_type == NMC_GENERIC_INFO_TYPE_GENERAL_LOGGING_LEVEL)
		return *d->level;
	else
		return *d->domains;
}

static const NmcMetaGenericInfo *const metagen_general_logging[_NMC_GENERIC_INFO_TYPE_GENERAL_LOGGING_NUM + 1] = {
#define _METAGEN_GENERAL_LOGGING(type, name) \
	[type] = NMC_META_GENERIC(name, .info_type = type, .get_fcn = _metagen_general_logging_get_fcn)
	_METAGEN_GENERAL_LOGGING (NMC_GENERIC_INFO_TYPE_GENERAL_LOGGING_LEVEL,   "LEVEL"),
	_METAGEN_GENERAL_LOGGING (NMC_GENERIC_INFO_TYPE_GENERAL_LOGGING_DOMAINS, "DOMAINS"),
};

/*****************************************************************************/

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

static void
quit (void)
{
	g_main_loop_quit (loop);
}

static gboolean
show_nm_status (NmCli *nmc, const char *pretty_header_name, const char *print_flds)
{
	gs_free_error GError *error = NULL;
	const char *fields_str;
	const char *fields_all =    print_flds ?: NMC_FIELDS_NM_STATUS_ALL;
	const char *fields_common = print_flds ?: NMC_FIELDS_NM_STATUS_COMMON;

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else
		fields_str = nmc->required_fields;

	if (!nmc_print (&nmc->nmc_config,
	                (gpointer[]) { nmc, NULL },
	                NULL,
	                pretty_header_name ?: N_("NetworkManager status"),
	                (const NMMetaAbstractInfo *const*) metagen_general_status,
	                fields_str,
	                &error)) {
		g_string_printf (nmc->return_text, _("Error: only these fields are allowed: %s"), fields_all);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return FALSE;
	}
	return TRUE;
}

static NMCResultCode
do_general_status (NmCli *nmc, int argc, char **argv)
{
	next_arg (nmc, &argc, &argv, NULL);
	if (nmc->complete)
		return nmc->return_value;

	show_nm_status (nmc, NULL, NULL);
	return nmc->return_value;
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
	gs_free_error GError *error = NULL;
	const char *fields_str = NULL;
	NMClientPermission perm;
	guint i;
	gpointer permissions[NM_CLIENT_PERMISSION_LAST + 1];

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0) {
	} else if (strcasecmp (nmc->required_fields, "all") == 0) {
	} else
		fields_str = nmc->required_fields;

	for (i = 0, perm = NM_CLIENT_PERMISSION_NONE + 1; perm <= NM_CLIENT_PERMISSION_LAST; perm++)
		permissions[i++] = GINT_TO_POINTER (perm);
	permissions[i++] = NULL;

	nm_cli_spawn_pager (nmc);

	if (!nmc_print (&nmc->nmc_config,
	                permissions,
	                NULL,
	                _("NetworkManager permissions"),
	                (const NMMetaAbstractInfo *const*) metagen_general_permissions,
	                fields_str,
	                &error)) {
		g_string_printf (nmc->return_text, _("Error: 'general permissions': %s"), error->message);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
	}

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
	next_arg (nmc, &argc, &argv, NULL);
	if (nmc->complete)
		return nmc->return_value;

	show_nm_permissions (nmc);
	return nmc->return_value;
}

static void
show_general_logging (NmCli *nmc)
{
	gs_free char *level_cache = NULL;
	gs_free char *domains_cache = NULL;
	gs_free_error GError *error = NULL;
	const char *fields_str = NULL;
	GetGeneralLoggingData d = {
		.level = &level_cache,
		.domains = &domains_cache,
	};

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0) {
	} else if (strcasecmp (nmc->required_fields, "all") == 0) {
	} else
		fields_str = nmc->required_fields;

	if (!nmc_print (&nmc->nmc_config,
	                (gpointer const []) { &d, NULL },
	                NULL,
	                _("NetworkManager logging"),
	                (const NMMetaAbstractInfo *const*) metagen_general_logging,
	                fields_str,
	                &error)) {
		g_string_printf (nmc->return_text, _("Error: 'general logging': %s"), error->message);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
	}
}

static void
nmc_complete_strings_nocase (const char *prefix, ...)
{
	va_list args;
	const char *candidate;
	int len;

	len = strlen (prefix);

	va_start (args, prefix);
	while ((candidate = va_arg (args, const char *))) {
		if (strncasecmp (prefix, candidate, len) == 0)
			g_print ("%s\n", candidate);
	}
	va_end (args);
}

static NMCResultCode
do_general_logging (NmCli *nmc, int argc, char **argv)
{
	gs_free_error GError *error = NULL;

	next_arg (nmc, &argc, &argv, NULL);
	if (argc == 0) {
		if (nmc->complete)
			return nmc->return_value;

		show_general_logging (nmc);
	} else {
		/* arguments provided -> set logging level and domains */
		const char *level = NULL;
		const char *domains = NULL;

		do {
			if (argc == 1 && nmc->complete)
				nmc_complete_strings (*argv, "level", "domains");

			if (matches (*argv, "level")) {
				argc--;
				argv++;
				if (!argc) {
					g_string_printf (nmc->return_text, _("Error: '%s' argument is missing."), *(argv-1));
					return NMC_RESULT_ERROR_USER_INPUT;
				}
				if (argc == 1 && nmc->complete) {
					nmc_complete_strings_nocase (*argv, "TRACE", "DEBUG", "INFO", "WARN",
					                             "ERR", "OFF", "KEEP", NULL);
				}
				level = *argv;
			} else if (matches (*argv, "domains")) {
				argc--;
				argv++;
				if (!argc) {
					g_string_printf (nmc->return_text, _("Error: '%s' argument is missing."), *(argv-1));
					return NMC_RESULT_ERROR_USER_INPUT;
				}
				if (argc == 1 && nmc->complete) {
					nmc_complete_strings_nocase (*argv, "PLATFORM", "RFKILL", "ETHER", "WIFI", "BT",
					                             "MB", "DHCP4", "DHCP6", "PPP", "WIFI_SCAN", "IP4",
					                             "IP6", "AUTOIP4", "DNS", "VPN", "SHARING", "SUPPLICANT",
					                             "AGENTS", "SETTINGS", "SUSPEND", "CORE", "DEVICE", "OLPC",
					                             "INFINIBAND", "FIREWALL", "ADSL", "BOND", "VLAN", "BRIDGE",
					                             "DBUS_PROPS", "TEAM", "CONCHECK", "DCB", "DISPATCH", "AUDIT",
					                             "SYSTEMD", "VPN_PLUGIN", "PROXY", "TC", NULL);
				}
				domains = *argv;
			} else {
				g_string_printf (nmc->return_text, _("Error: property '%s' is not known."), *argv);
				return NMC_RESULT_ERROR_USER_INPUT;
			}
		} while (next_arg (nmc, &argc, &argv, NULL) == 0);

		if (nmc->complete)
			return nmc->return_value;

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
	next_arg (nmc, &argc, &argv, NULL);
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

		if (next_arg (nmc, &argc, &argv, NULL) == 0)
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
	next_arg (nmc, &argc, &argv, NULL);

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
	if (nmc->nmc_config.print_output == NMC_PRINT_NORMAL)
		nmc->nmc_config_mutable.print_output = NMC_PRINT_TERSE;

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
	next_arg (nmc, &argc, &argv, NULL);
	return do_networking_on_off (nmc, argc, argv, TRUE);
}

static NMCResultCode
do_networking_off (NmCli *nmc, int argc, char **argv)
{
	next_arg (nmc, &argc, &argv, NULL);
	return do_networking_on_off (nmc, argc, argv, FALSE);
}

static NMCResultCode
do_networking_connectivity (NmCli *nmc, int argc, char **argv)
{
	next_arg (nmc, &argc, &argv, NULL);
	if (nmc->complete) {
		if (argc == 1)
			nmc_complete_strings (*argv, "check");
		return nmc->return_value;
	}

	if (!argc) {
		/* no arguments -> get current state */
		nmc_switch_show (nmc, NMC_FIELDS_NM_CONNECTIVITY, N_("Connectivity"));
	} else if (matches (*argv, "check")) {
		gs_free_error GError *error = NULL;

		/* Register polkit agent */
		nmc_start_polkit_agent_start_try (nmc);

		nm_client_check_connectivity (nmc->client, NULL, &error);
		if (error) {
			g_string_printf (nmc->return_text, _("Error: %s."), error->message);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		} else
			nmc_switch_show (nmc, NMC_FIELDS_NM_CONNECTIVITY, N_("Connectivity"));
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
	next_arg (nmc, &argc, &argv, NULL);
	if (nmc->complete)
		return nmc->return_value;

	nmc_switch_show (nmc, NMC_FIELDS_NM_NETWORKING, N_("Networking"));

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
	next_arg (nmc, &argc, &argv, NULL);
	nmc_do_cmd (nmc, networking_cmds, *argv, argc, argv);

	return nmc->return_value;
}

static NMCResultCode
do_radio_all (NmCli *nmc, int argc, char **argv)
{
	gboolean enable_flag;

	next_arg (nmc, &argc, &argv, NULL);
	if (argc == 0) {
		if (nmc->complete)
			return nmc->return_value;

		/* no argument, show all radio switches */
		show_nm_status (nmc, N_("Radio switches"), NMC_FIELDS_NM_STATUS_RADIO);
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

	next_arg (nmc, &argc, &argv, NULL);
	if (argc == 0) {
		if (nmc->complete)
			return nmc->return_value;

		/* no argument, show current Wi-Fi state */
		nmc_switch_show (nmc, NMC_FIELDS_NM_WIFI, N_("Wi-Fi radio switch"));
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

	next_arg (nmc, &argc, &argv, NULL);
	if (argc == 0) {
		if (nmc->complete)
			return nmc->return_value;

		/* no argument, show current WWAN (mobile broadband) state */
		nmc_switch_show (nmc, NMC_FIELDS_NM_WWAN, N_("WWAN radio switch"));
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
	next_arg (nmc, &argc, &argv, NULL);

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
	str = nmc_colorize (&nmc->nmc_config,
	                    running ? NM_META_COLOR_MANAGER_RUNNING : NM_META_COLOR_MANAGER_STOPPED,
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
	str = nmc_colorize (&nmc->nmc_config, connectivity_to_color (connectivity),
	                    _("Connectivity is now '%s'\n"),
	                    gettext (nm_connectivity_to_string (connectivity)));
	g_print ("%s", str);
	g_free (str);
}

static void
client_state (NMClient *client, GParamSpec *param, NmCli *nmc)
{
	NMState state;
	char *str;

	g_object_get (client, NM_CLIENT_STATE, &state, NULL);
	str = nmc_colorize (&nmc->nmc_config, state_to_color (state),
	                    _("Networkmanager is now in the '%s' state\n"),
	                    gettext (nm_state_to_string (state)));
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
		tmp = nmc_colorize (&nmc->nmc_config, NM_META_COLOR_DEVICE_FIRMWARE_MISSING, _("fw missing"));
		g_string_append_printf (outbuf, "%s, ", tmp);
		g_free (tmp);
	}
	if (nm_device_get_nm_plugin_missing (device)) {
		tmp = nmc_colorize (&nmc->nmc_config, NM_META_COLOR_DEVICE_PLUGIN_MISSING, _("plugin missing"));
		g_string_append_printf (outbuf, "%s, ", tmp);
		g_free (tmp);
	}
	if (nm_device_is_software (device))
		g_string_append_printf (outbuf, "%s, ", _("sw"));
	else
		g_string_append_printf (outbuf, "%s, ", _("hw"));

	if (!NM_IN_STRSET (nm_device_get_ip_iface (device),
	                   NULL,
	                   nm_device_get_iface (device)))
		g_string_append_printf (outbuf, "%s %s, ", _("iface"), nm_device_get_ip_iface (device));

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
		g_string_append_printf (outbuf, "%s %s, ", _("master"),
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
	NMMetaColor color;
	NMDnsEntry *dns;
	char *tmp;
	int i;

	next_arg (nmc, &argc, &argv, NULL);

	/* Register polkit agent */
	nmc_start_polkit_agent_start_try (nmc);

	nm_cli_spawn_pager (nmc);

	/* The VPN connections don't have devices (yet?). */
	p = nm_client_get_active_connections (nmc->client);
	for (i = 0; i < p->len; i++) {
		NMActiveConnectionState state;

		ac = p->pdata[i];

		if (!nm_active_connection_get_vpn (ac))
			continue;

		state = nm_active_connection_get_state (ac);
		color = nmc_active_connection_state_to_color (state);
		tmp = nmc_colorize (&nmc->nmc_config, color, _("%s VPN connection"),
		                    nm_active_connection_get_id (ac));
		g_print ("%s\n", tmp);
		g_free (tmp);

		ac_overview (nmc, ac);
		g_print ("\n");
	}

	devices = nmc_get_devices_sorted (nmc->client);
	for (i = 0; devices[i]; i++) {
		NMDeviceState state;

		ac = nm_device_get_active_connection (devices[i]);

		state = nm_device_get_state (devices[i]);
		color = nmc_device_state_to_color (state);
		tmp = nmc_colorize (&nmc->nmc_config, color, "%s: %s%s%s",
		                    nm_device_get_iface (devices[i]),
		                    gettext (nmc_device_state_to_string (state)),
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
	           "Consult nmcli(1) and nmcli-examples(7) manual pages for complete usage details.\n"));

	return NMC_RESULT_SUCCESS;
}

/*
 * Entry point function for 'nmcli monitor'
 */
NMCResultCode
do_monitor (NmCli *nmc, int argc, char **argv)
{
	next_arg (nmc, &argc, &argv, NULL);

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

		str = nmc_colorize (&nmc->nmc_config, NM_META_COLOR_MANAGER_STOPPED,
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
