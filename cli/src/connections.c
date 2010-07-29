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

#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <netinet/ether.h>

#include <nm-client.h>
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-pppoe.h>
#include <nm-setting-wireless.h>
#include <nm-setting-gsm.h>
#include <nm-setting-cdma.h>
#include <nm-setting-bluetooth.h>
#include <nm-setting-olpc-mesh.h>
#include <nm-device-ethernet.h>
#include <nm-device-wifi.h>
#include <nm-gsm-device.h>
#include <nm-cdma-device.h>
#include <nm-device-bt.h>
//#include <nm-device-olpc-mesh.h>
#include <nm-remote-settings.h>
#include <nm-remote-settings-system.h>
#include <nm-settings-interface.h>
#include <nm-settings-connection-interface.h>
#include <nm-vpn-connection.h>

#include "utils.h"
#include "settings.h"
#include "connections.h"


/* Available fields for 'con status' */
static NmcOutputField nmc_fields_con_status[] = {
	{"NAME",          N_("NAME"),         25, NULL, 0},  /* 0 */
	{"UUID",          N_("UUID"),         38, NULL, 0},  /* 1 */
	{"DEVICES",       N_("DEVICES"),      10, NULL, 0},  /* 2 */
	{"SCOPE",         N_("SCOPE"),         8, NULL, 0},  /* 3 */
	{"DEFAULT",       N_("DEFAULT"),       8, NULL, 0},  /* 4 */
	{"DBUS-SERVICE",  N_("DBUS-SERVICE"), 45, NULL, 0},  /* 5 */
	{"SPEC-OBJECT",   N_("SPEC-OBJECT"),  10, NULL, 0},  /* 6 */
	{"VPN",           N_("VPN"),           5, NULL, 0},  /* 7 */
	{NULL,            NULL,                0, NULL, 0}
};
#define NMC_FIELDS_CON_STATUS_ALL     "NAME,UUID,DEVICES,SCOPE,DEFAULT,VPN,DBUS-SERVICE,SPEC-OBJECT"
#define NMC_FIELDS_CON_STATUS_COMMON  "NAME,UUID,DEVICES,SCOPE,DEFAULT,VPN"

/* Available fields for 'con list' */
static NmcOutputField nmc_fields_con_list[] = {
	{"NAME",            N_("NAME"),           25, NULL, 0},  /* 0 */
	{"UUID",            N_("UUID"),           38, NULL, 0},  /* 1 */
	{"TYPE",            N_("TYPE"),           17, NULL, 0},  /* 2 */
	{"SCOPE",           N_("SCOPE"),           8, NULL, 0},  /* 3 */
	{"TIMESTAMP",       N_("TIMESTAMP"),      12, NULL, 0},  /* 4 */
	{"TIMESTAMP-REAL",  N_("TIMESTAMP-REAL"), 34, NULL, 0},  /* 5 */
	{"AUTOCONNECT",     N_("AUTOCONNECT"),    13, NULL, 0},  /* 6 */
	{"READONLY",        N_("READONLY"),       10, NULL, 0},  /* 7 */
	{NULL,              NULL,                  0, NULL, 0}
};
#define NMC_FIELDS_CON_LIST_ALL     "NAME,UUID,TYPE,SCOPE,TIMESTAMP,TIMESTAMP-REAL,AUTOCONNECT,READONLY"
#define NMC_FIELDS_CON_LIST_COMMON  "NAME,UUID,TYPE,SCOPE,TIMESTAMP-REAL"


/* Helper macro to define fields */
#define SETTING_FIELD(setting, width) { setting, N_(setting), width, NULL, 0 }

/* Available settings for 'con list id/uuid <con>' */
static NmcOutputField nmc_fields_settings_names[] = {
	SETTING_FIELD (NM_SETTING_CONNECTION_SETTING_NAME, 0),            /* 0 */
	SETTING_FIELD (NM_SETTING_WIRED_SETTING_NAME, 0),                 /* 1 */
	SETTING_FIELD (NM_SETTING_802_1X_SETTING_NAME, 0),                /* 2 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SETTING_NAME, 0),              /* 3 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, 0),     /* 4 */
	SETTING_FIELD (NM_SETTING_IP4_CONFIG_SETTING_NAME, 0),            /* 5 */
	SETTING_FIELD (NM_SETTING_IP6_CONFIG_SETTING_NAME, 0),            /* 6 */
	SETTING_FIELD (NM_SETTING_SERIAL_SETTING_NAME, 0),                /* 7 */
	SETTING_FIELD (NM_SETTING_PPP_SETTING_NAME, 0),                   /* 8 */
	SETTING_FIELD (NM_SETTING_PPPOE_SETTING_NAME, 0),                 /* 9 */
	SETTING_FIELD (NM_SETTING_GSM_SETTING_NAME, 0),                   /* 10 */
	SETTING_FIELD (NM_SETTING_CDMA_SETTING_NAME, 0),                  /* 11 */
	SETTING_FIELD (NM_SETTING_BLUETOOTH_SETTING_NAME, 0),             /* 12 */
	SETTING_FIELD (NM_SETTING_OLPC_MESH_SETTING_NAME, 0),             /* 13 */
	SETTING_FIELD (NM_SETTING_VPN_SETTING_NAME, 0),                   /* 14 */
	{NULL, NULL, 0, NULL, 0}
};
#define NMC_FIELDS_SETTINGS_NAMES_ALL    NM_SETTING_CONNECTION_SETTING_NAME","\
                                         NM_SETTING_WIRED_SETTING_NAME","\
                                         NM_SETTING_802_1X_SETTING_NAME","\
                                         NM_SETTING_WIRELESS_SETTING_NAME","\
                                         NM_SETTING_WIRELESS_SECURITY_SETTING_NAME","\
                                         NM_SETTING_IP4_CONFIG_SETTING_NAME","\
                                         NM_SETTING_IP6_CONFIG_SETTING_NAME","\
                                         NM_SETTING_SERIAL_SETTING_NAME","\
                                         NM_SETTING_PPP_SETTING_NAME","\
                                         NM_SETTING_PPPOE_SETTING_NAME","\
                                         NM_SETTING_GSM_SETTING_NAME","\
                                         NM_SETTING_CDMA_SETTING_NAME","\
                                         NM_SETTING_BLUETOOTH_SETTING_NAME","\
                                         NM_SETTING_OLPC_MESH_SETTING_NAME","\
                                         NM_SETTING_VPN_SETTING_NAME


typedef struct {
	NmCli *nmc;
	int argc;
	char **argv;
} ArgsInfo;

extern GMainLoop *loop;   /* glib main loop variable */

static ArgsInfo args_info;

/* static function prototypes */
static void usage (void);
static void quit (void);
static void show_connection (NMConnection *data, gpointer user_data);
static NMConnection *find_connection (GSList *list, const char *filter_type, const char *filter_val);
static gboolean find_device_for_connection (NmCli *nmc, NMConnection *connection, const char *iface, const char *ap,
                                            NMDevice **device, const char **spec_object, GError **error);
static const char *active_connection_state_to_string (NMActiveConnectionState state);
static void active_connection_state_cb (NMActiveConnection *active, GParamSpec *pspec, gpointer user_data);
static void activate_connection_cb (gpointer user_data, const char *path, GError *error);
static void get_connections_cb (NMSettingsInterface *settings, gpointer user_data);
static NMCResultCode do_connections_list (NmCli *nmc, int argc, char **argv);
static NMCResultCode do_connections_status (NmCli *nmc, int argc, char **argv);
static NMCResultCode do_connection_up (NmCli *nmc, int argc, char **argv);
static NMCResultCode do_connection_down (NmCli *nmc, int argc, char **argv);

static void
usage (void)
{
	fprintf (stderr,
	 	 _("Usage: nmcli con { COMMAND | help }\n"
		 "  COMMAND := { list | status | up | down }\n\n"
		 "  list [id <id> | uuid <id> | system | user]\n"
		 "  status\n"
		 "  up id <id> | uuid <id> [iface <iface>] [ap <hwaddr>] [--nowait] [--timeout <timeout>]\n"
		 "  down id <id> | uuid <id>\n"));
}

/* quit main loop */
static void
quit (void)
{
	g_main_loop_quit (loop);  /* quit main loop */
}

static gboolean
nmc_connection_detail (NMConnection *connection, NmCli *nmc)
{
	NMSetting *setting;
	GError *error = NULL;
	GArray *print_settings_array;
	int i;
	char *fields_str;
	char *fields_all =    NMC_FIELDS_SETTINGS_NAMES_ALL;
	char *fields_common = NMC_FIELDS_SETTINGS_NAMES_ALL;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;
	gboolean was_output = FALSE;

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else
		fields_str = nmc->required_fields;

	print_settings_array = parse_output_fields (fields_str, nmc_fields_settings_names, &error);
	if (error) {
		if (error->code == 0)
			g_string_printf (nmc->return_text, _("Error: 'con list': %s"), error->message);
		else
			g_string_printf (nmc->return_text, _("Error: 'con list': %s; allowed fields: %s"), error->message, NMC_FIELDS_SETTINGS_NAMES_ALL);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return FALSE;
	}

	nmc->allowed_fields = nmc_fields_settings_names;
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ONLY;
	nmc->print_fields.header_name = _("Connection details");
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTINGS_NAMES_ALL, nmc->allowed_fields, NULL);
	print_fields (nmc->print_fields, nmc->allowed_fields);

	/* Loop through the required settings and print them. */
	for (i = 0; i < print_settings_array->len; i++) {
		int section_idx = g_array_index (print_settings_array, int, i);

		if (nmc->print_output != NMC_PRINT_TERSE && !nmc->multiline_output && was_output)
			printf ("\n"); /* Empty line */

		was_output = FALSE;

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[0].name)) {
			setting = nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
			if (setting) {
				setting_connection_details (setting, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[1].name)) {
			setting = nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED);
			if (setting) {
				setting_wired_details (setting, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[2].name)) {
			setting = nm_connection_get_setting (connection, NM_TYPE_SETTING_802_1X);
			if (setting) {
				setting_802_1X_details (setting, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[3].name)) {
			setting = nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS);
			if (setting) {
				setting_wireless_details (setting, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[4].name)) {
			setting = nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS_SECURITY);
			if (setting) {
				setting_wireless_security_details (setting, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[5].name)) {
			setting = nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
			if (setting) {
				setting_ip4_config_details (setting, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[6].name)) {
			setting = nm_connection_get_setting (connection, NM_TYPE_SETTING_IP6_CONFIG);
			if (setting) {
				setting_ip6_config_details (setting, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[7].name)) {
			setting = nm_connection_get_setting (connection, NM_TYPE_SETTING_SERIAL);
			if (setting) {
				setting_serial_details (setting, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[8].name)) {
			setting = nm_connection_get_setting (connection, NM_TYPE_SETTING_PPP);
			if (setting) {
				setting_ppp_details (setting, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[9].name)) {
			setting = nm_connection_get_setting (connection, NM_TYPE_SETTING_PPPOE);
			if (setting) {
				setting_pppoe_details (setting, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[10].name)) {
			setting = nm_connection_get_setting (connection, NM_TYPE_SETTING_GSM);
			if (setting) {
				setting_gsm_details (setting, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[11].name)) {
			setting = nm_connection_get_setting (connection, NM_TYPE_SETTING_CDMA);
			if (setting) {
				setting_cdma_details (setting, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[12].name)) {
			setting = nm_connection_get_setting (connection, NM_TYPE_SETTING_BLUETOOTH);
			if (setting) {
				setting_bluetooth_details (setting, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[13].name)) {
			setting = nm_connection_get_setting (connection, NM_TYPE_SETTING_OLPC_MESH);
			if (setting) {
				setting_olpc_mesh_details (setting, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[14].name)) {
			setting = nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
			if (setting) {
				setting_vpn_details (setting, nmc);
				was_output = TRUE;
				continue;
			}
		}
	}

	if (print_settings_array)
		g_array_free (print_settings_array, FALSE);

	return NMC_RESULT_SUCCESS;
}

static void
show_connection (NMConnection *data, gpointer user_data)
{
	NMConnection *connection = (NMConnection *) data;
	NmCli *nmc = (NmCli *) user_data;
	NMSettingConnection *s_con;
	guint64 timestamp;
	char *timestamp_str;
	char timestamp_real_str[64];

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	if (s_con) {
		/* Obtain field values */
		timestamp = nm_setting_connection_get_timestamp (s_con);
		timestamp_str = g_strdup_printf ("%" G_GUINT64_FORMAT, timestamp);
		strftime (timestamp_real_str, sizeof (timestamp_real_str), "%c", localtime ((time_t *) &timestamp));
		nmc->allowed_fields[0].value = nm_setting_connection_get_id (s_con);
		nmc->allowed_fields[1].value = nm_setting_connection_get_uuid (s_con);
		nmc->allowed_fields[2].value = nm_setting_connection_get_connection_type (s_con);
		nmc->allowed_fields[3].value = nm_connection_get_scope (connection) == NM_CONNECTION_SCOPE_SYSTEM ? _("system") : _("user");
		nmc->allowed_fields[4].value = timestamp_str;
		nmc->allowed_fields[5].value = timestamp ? timestamp_real_str : _("never");
		nmc->allowed_fields[6].value = nm_setting_connection_get_autoconnect (s_con) ? _("yes") : _("no");
		nmc->allowed_fields[7].value = nm_setting_connection_get_read_only (s_con) ? _("yes") : _("no");

		nmc->print_fields.flags &= ~NMC_PF_FLAG_MAIN_HEADER_ADD & ~NMC_PF_FLAG_MAIN_HEADER_ONLY & ~NMC_PF_FLAG_FIELD_NAMES; /* Clear header flags */
		print_fields (nmc->print_fields, nmc->allowed_fields);

		g_free (timestamp_str);
	}
}

static NMConnection *
find_connection (GSList *list, const char *filter_type, const char *filter_val)
{
	NMSettingConnection *s_con;
	NMConnection *connection;
	GSList *iterator;
	const char *id;
	const char *uuid;

	iterator = list;
	while (iterator) {
		connection = NM_CONNECTION (iterator->data);
		s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
		if (s_con) {
			id = nm_setting_connection_get_id (s_con);
			uuid = nm_setting_connection_get_uuid (s_con);
			if (filter_type) {
				if ((strcmp (filter_type, "id") == 0 && strcmp (filter_val, id) == 0) ||
				    (strcmp (filter_type, "uuid") == 0 && strcmp (filter_val, uuid) == 0)) {
					return connection;
				}
			}
		}
		iterator = g_slist_next (iterator);
	}

	return NULL;
}

static NMCResultCode
do_connections_list (NmCli *nmc, int argc, char **argv)
{
	GError *error1 = NULL;
	GError *error2 = NULL;
	char *fields_str;
	char *fields_all =    NMC_FIELDS_CON_LIST_ALL;
	char *fields_common = NMC_FIELDS_CON_LIST_COMMON;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;
	gboolean valid_param_specified = FALSE;

	nmc->should_wait = FALSE;

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else
		fields_str = nmc->required_fields;

	nmc->allowed_fields = nmc_fields_con_list;
	nmc->print_fields.indices = parse_output_fields (fields_str, nmc->allowed_fields, &error1);
	/* error1 is checked later - it's not valid for connection details */

	if (argc == 0) {
		if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error2))
			goto error;
		if (error1)
			goto error;
		valid_param_specified = TRUE;

		nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ADD | NMC_PF_FLAG_FIELD_NAMES;
		nmc->print_fields.header_name = _("System connections");
		print_fields (nmc->print_fields, nmc->allowed_fields);
		g_slist_foreach (nmc->system_connections, (GFunc) show_connection, nmc);

		nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ADD | NMC_PF_FLAG_FIELD_NAMES;
		nmc->print_fields.header_name = _("User connections");
		print_fields (nmc->print_fields, nmc->allowed_fields);
		g_slist_foreach (nmc->user_connections, (GFunc) show_connection, nmc);
	}
	else {
		while (argc > 0) {
			if (strcmp (*argv, "id") == 0 || strcmp (*argv, "uuid") == 0) {
				const char *selector = *argv;
				NMConnection *con1;
				NMConnection *con2;

				if (next_arg (&argc, &argv) != 0) {
					g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					return nmc->return_value;
				}
				valid_param_specified = TRUE;
				if (!nmc->mode_specified)
					nmc->multiline_output = TRUE;  /* multiline mode is default for 'con list id|uuid' */

				con1 = find_connection (nmc->system_connections, selector, *argv);
				con2 = find_connection (nmc->user_connections, selector, *argv);
				if (con1) nmc_connection_detail (con1, nmc);
				if (con2) nmc_connection_detail (con2, nmc);
				if (!con1 && !con2) {
					g_string_printf (nmc->return_text, _("Error: %s - no such connection."), *argv);
					nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
				}
				break;
			}
			else if (strcmp (*argv, "system") == 0) {
				if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error2))
					goto error;
				if (error1)
					goto error;
				valid_param_specified = TRUE;

				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ADD | NMC_PF_FLAG_FIELD_NAMES;
				nmc->print_fields.header_name = _("System connections");
				print_fields (nmc->print_fields, nmc->allowed_fields);
				g_slist_foreach (nmc->system_connections, (GFunc) show_connection, nmc);
				break;
			}
			else if (strcmp (*argv, "user") == 0) {
				if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error2))
					goto error;
				if (error1)
					goto error;
				valid_param_specified = TRUE;

				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ADD | NMC_PF_FLAG_FIELD_NAMES;
				nmc->print_fields.header_name = _("User connections");
				print_fields (nmc->print_fields, nmc->allowed_fields);
				g_slist_foreach (nmc->user_connections, (GFunc) show_connection, nmc);
				break;
			}
			else {
				fprintf (stderr, _("Unknown parameter: %s\n"), *argv);
			}

			argc--;
			argv++;
		}
	}

	if (!valid_param_specified) {
		g_string_printf (nmc->return_text, _("Error: no valid parameter specified."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
	}
	return nmc->return_value;

error:
	if (error1) {
		if (error1->code == 0)
			g_string_printf (nmc->return_text, _("Error: 'con list': %s"), error1->message);
		else
			g_string_printf (nmc->return_text, _("Error: 'con list': %s; allowed fields: %s"), error1->message, NMC_FIELDS_CON_LIST_ALL);
		g_error_free (error1);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
	}
	if (error2) {
		g_string_printf (nmc->return_text, _("Error: %s."), error2->message);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		g_error_free (error2);
	}

	return nmc->return_value;
}

typedef struct {
	NmCli *nmc;
	NMConnectionScope scope;
} StatusInfo;

static void
show_active_connection (gpointer data, gpointer user_data)
{
	NMActiveConnection *active = NM_ACTIVE_CONNECTION (data);
	StatusInfo *info = (StatusInfo *) user_data;
	GSList *con_list, *iter;
	const char *active_path;
	NMConnectionScope active_service_scope;
	NMSettingConnection *s_con;
	const GPtrArray *devices;
	GString *dev_str;
	int i;

	active_path = nm_active_connection_get_connection (active);
	active_service_scope = nm_active_connection_get_scope (active);

	if (active_service_scope != info->scope)
		return;

	/* Get devices of the active connection */
	dev_str = g_string_new (NULL);
	devices = nm_active_connection_get_devices (active);
	for (i = 0; devices && (i < devices->len); i++) {
		NMDevice *device = g_ptr_array_index (devices, i);

		g_string_append (dev_str, nm_device_get_iface (device));
		g_string_append_c (dev_str, ',');
	}
	if (dev_str->len > 0)
		g_string_truncate (dev_str, dev_str->len - 1);  /* Cut off last ',' */

	con_list = (info->scope == NM_CONNECTION_SCOPE_SYSTEM) ? info->nmc->system_connections : info->nmc->user_connections;
	for (iter = con_list; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = (NMConnection *) iter->data;
		const char *con_path = nm_connection_get_path (connection);

		if (!strcmp (active_path, con_path)) {
			/* This connection is active */
			s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
			g_assert (s_con != NULL);

			/* Obtain field values */
			info->nmc->allowed_fields[0].value = nm_setting_connection_get_id (s_con);
			info->nmc->allowed_fields[1].value = nm_setting_connection_get_uuid (s_con);
			info->nmc->allowed_fields[2].value = dev_str->str;
			info->nmc->allowed_fields[3].value = active_service_scope == NM_CONNECTION_SCOPE_SYSTEM ? _("system") : _("user");
			info->nmc->allowed_fields[4].value = nm_active_connection_get_default (active) ? _("yes") : _("no");
			info->nmc->allowed_fields[5].value = nm_active_connection_get_service_name (active);
			info->nmc->allowed_fields[6].value = nm_active_connection_get_specific_object (active);
			info->nmc->allowed_fields[7].value = NM_IS_VPN_CONNECTION (active) ? _("yes") : _("no");

			info->nmc->print_fields.flags &= ~NMC_PF_FLAG_MAIN_HEADER_ADD & ~NMC_PF_FLAG_MAIN_HEADER_ONLY & ~NMC_PF_FLAG_FIELD_NAMES; /* Clear header flags */
			print_fields (info->nmc->print_fields, info->nmc->allowed_fields);
			break;
		}
	}

	g_string_free (dev_str, TRUE);
}

static NMCResultCode
do_connections_status (NmCli *nmc, int argc, char **argv)
{
	const GPtrArray *active_cons;
	GError *error = NULL;
	StatusInfo *info;
	char *fields_str;
	char *fields_all =    NMC_FIELDS_CON_STATUS_ALL;
	char *fields_common = NMC_FIELDS_CON_STATUS_COMMON;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	nmc->should_wait = FALSE;

	/* create NMClient */
	if (!nmc->get_client (nmc))
		return nmc->return_value;

	active_cons = nm_client_get_active_connections (nmc->client);

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else
		fields_str = nmc->required_fields;

	nmc->allowed_fields = nmc_fields_con_status;
	nmc->print_fields.indices = parse_output_fields (fields_str, nmc->allowed_fields, &error);

	if (error) {
		if (error->code == 0)
			g_string_printf (nmc->return_text, _("Error: 'con status': %s"), error->message);
		else
			g_string_printf (nmc->return_text, _("Error: 'con status': %s; allowed fields: %s"), error->message, NMC_FIELDS_CON_STATUS_ALL);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ADD | NMC_PF_FLAG_FIELD_NAMES;
	nmc->print_fields.header_name = _("Active connections");
	print_fields (nmc->print_fields, nmc->allowed_fields);

	if (active_cons && active_cons->len) {
		info = g_malloc0 (sizeof (StatusInfo));
		info->nmc = nmc;
		info->scope = NM_CONNECTION_SCOPE_SYSTEM;
		g_ptr_array_foreach ((GPtrArray *) active_cons, show_active_connection, (gpointer) info);
		info->scope = NM_CONNECTION_SCOPE_USER;
		g_ptr_array_foreach ((GPtrArray *) active_cons, show_active_connection, (gpointer) info);
		g_free (info);
	}

error:

	return nmc->return_value;
}

/* --------------------
 * These function should be moved to libnm-glib in the end.
 */
static gboolean
check_ethernet_compatible (NMDeviceEthernet *device, NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	const char *connection_type;
	gboolean is_pppoe = FALSE;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	connection_type = nm_setting_connection_get_connection_type (s_con);
	if (   strcmp (connection_type, NM_SETTING_WIRED_SETTING_NAME)
	    && strcmp (connection_type, NM_SETTING_PPPOE_SETTING_NAME)) {
		g_set_error (error, 0, 0,
		             "The connection was not a wired or PPPoE connection.");
		return FALSE;
	}

	if (!strcmp (connection_type, NM_SETTING_PPPOE_SETTING_NAME))
		is_pppoe = TRUE;

	s_wired = (NMSettingWired *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRED);
	/* Wired setting is optional for PPPoE */
	if (!is_pppoe && !s_wired) {
		g_set_error (error, 0, 0,
		             "The connection was not a valid wired connection.");
		return FALSE;
	}

	if (s_wired) {
		const GByteArray *mac;
		const char *device_mac_str;
		struct ether_addr *device_mac;

		device_mac_str = nm_device_ethernet_get_permanent_hw_address (device);
		device_mac = ether_aton (device_mac_str);
		if (!device_mac) {
			g_set_error (error, 0, 0, "Invalid device MAC address.");
			return FALSE;
		}

		mac = nm_setting_wired_get_mac_address (s_wired);
		if (mac && memcmp (mac->data, device_mac->ether_addr_octet, ETH_ALEN)) {
			g_set_error (error, 0, 0,
			             "The connection's MAC address did not match this device.");
			return FALSE;
		}
	}

	// FIXME: check bitrate against device capabilities

	return TRUE;
}

static gboolean
check_wifi_compatible (NMDeviceWifi *device, NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_WIRELESS_SETTING_NAME)) {
		g_set_error (error, 0, 0,
		             "The connection was not a WiFi connection.");
		return FALSE;
	}

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
	if (!s_wireless) {
		g_set_error (error, 0, 0,
		             "The connection was not a valid WiFi connection.");
		return FALSE;
	}

	if (s_wireless) {
		const GByteArray *mac;
		const char *device_mac_str;
		struct ether_addr *device_mac;

		device_mac_str = nm_device_wifi_get_permanent_hw_address (device);
		device_mac = ether_aton (device_mac_str);
		if (!device_mac) {
			g_set_error (error, 0, 0, "Invalid device MAC address.");
			return FALSE;
		}

		mac = nm_setting_wireless_get_mac_address (s_wireless);
		if (mac && memcmp (mac->data, device_mac->ether_addr_octet, ETH_ALEN)) {
			g_set_error (error, 0, 0,
		        	     "The connection's MAC address did not match this device.");
			return FALSE;
		}
	}

	// FIXME: check channel/freq/band against bands the hardware supports
	// FIXME: check encryption against device capabilities
	// FIXME: check bitrate against device capabilities

	return TRUE;
}

static gboolean
check_bt_compatible (NMDeviceBt *device, NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;
	NMSettingBluetooth *s_bt;
	const GByteArray *array;
	char *str;
	const char *device_hw_str;
	int addr_match = FALSE;
	const char *bt_type_str;
	guint32 bt_type, bt_capab;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_BLUETOOTH_SETTING_NAME)) {
		g_set_error (error, 0, 0,
		             "The connection was not a Bluetooth connection.");
		return FALSE;
	}

	s_bt = NM_SETTING_BLUETOOTH (nm_connection_get_setting (connection, NM_TYPE_SETTING_BLUETOOTH));
	if (!s_bt) {
		g_set_error (error, 0, 0,
		             "The connection was not a valid Bluetooth connection.");
		return FALSE;
	}

	array = nm_setting_bluetooth_get_bdaddr (s_bt);
	if (!array || (array->len != ETH_ALEN)) {
		g_set_error (error, 0, 0,
		             "The connection did not contain a valid Bluetooth address.");
		return FALSE;
	}

	bt_type_str = nm_setting_bluetooth_get_connection_type (s_bt);
	g_assert (bt_type_str);

	bt_type = NM_BT_CAPABILITY_NONE;
	if (!strcmp (bt_type_str, NM_SETTING_BLUETOOTH_TYPE_DUN))
		bt_type = NM_BT_CAPABILITY_DUN;
	else if (!strcmp (bt_type_str, NM_SETTING_BLUETOOTH_TYPE_PANU))
		bt_type = NM_BT_CAPABILITY_NAP;

	bt_capab = nm_device_bt_get_capabilities (device);
	if (!(bt_type & bt_capab)) {
		g_set_error (error, 0, 0,
		             "The connection was not compatible with the device's capabilities.");
		return FALSE;
	}

	device_hw_str = nm_device_bt_get_hw_address (device);

	str = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X",
	                       array->data[0], array->data[1], array->data[2],
	                       array->data[3], array->data[4], array->data[5]);
	addr_match = !strcmp (device_hw_str, str);
	g_free (str);

	return addr_match;
}

#if 0
static gboolean
check_olpc_mesh_compatible (NMDeviceOlpcMesh *device, NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;
	NMSettingOlpcMesh *s_mesh;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_OLPC_MESH_SETTING_NAME)) {
		g_set_error (error, 0, 0,
		             "The connection was not a Mesh connection.");
		return FALSE;
	}

	s_mesh = NM_SETTING_OLPC_MESH (nm_connection_get_setting (connection, NM_TYPE_SETTING_OLPC_MESH));
	if (!s_mesh) {
		g_set_error (error, 0, 0,
		             "The connection was not a valid Mesh connection.");
		return FALSE;
	}

	return TRUE;
}
#endif

static gboolean
nm_device_is_connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	if (NM_IS_DEVICE_ETHERNET (device))
		return check_ethernet_compatible (NM_DEVICE_ETHERNET (device), connection, error);
	else if (NM_IS_DEVICE_WIFI (device))
		return check_wifi_compatible (NM_DEVICE_WIFI (device), connection, error);
	else if (NM_IS_DEVICE_BT (device))
		return check_bt_compatible (NM_DEVICE_BT (device), connection, error);
//	else if (NM_IS_DEVICE_OLPC_MESH (device))
//		return check_olpc_mesh_compatible (NM_DEVICE_OLPC_MESH (device), connection, error);

	g_set_error (error, 0, 0, "unhandled device type '%s'", G_OBJECT_TYPE_NAME (device));
	return FALSE;
}


/**
 * nm_client_get_active_connection_by_path:
 * @client: a #NMClient
 * @object_path: the object path to search for
 *
 * Gets a #NMActiveConnection from a #NMClient.
 *
 * Returns: the #NMActiveConnection for the given @object_path or %NULL if none is found.
 **/
static NMActiveConnection *
nm_client_get_active_connection_by_path (NMClient *client, const char *object_path)
{
	const GPtrArray *actives;
	int i;
	NMActiveConnection *active = NULL;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (object_path, NULL);

	actives = nm_client_get_active_connections (client);
	if (!actives)
		return NULL;

	for (i = 0; i < actives->len; i++) {
		NMActiveConnection *candidate = g_ptr_array_index (actives, i);
		if (!strcmp (nm_object_get_path (NM_OBJECT (candidate)), object_path)) {
			active = candidate;
			break;
		}
	}

	return active;
}
/* -------------------- */

static NMActiveConnection *
get_default_active_connection (NmCli *nmc, NMDevice **device)
{
	NMActiveConnection *default_ac = NULL;
	NMDevice *non_default_device = NULL;
	NMActiveConnection *non_default_ac = NULL;
	const GPtrArray *connections;
	int i;

	g_return_val_if_fail (nmc != NULL, NULL);
	g_return_val_if_fail (device != NULL, NULL);
	g_return_val_if_fail (*device == NULL, NULL);

	connections = nm_client_get_active_connections (nmc->client);
	for (i = 0; connections && (i < connections->len); i++) {
		NMActiveConnection *candidate = g_ptr_array_index (connections, i);
		const GPtrArray *devices;

		devices = nm_active_connection_get_devices (candidate);
		if (!devices || !devices->len)
			continue;

		if (nm_active_connection_get_default (candidate)) {
			if (!default_ac) {
				*device = g_ptr_array_index (devices, 0);
				default_ac = candidate;
			}
		} else {
			if (!non_default_ac) {
				non_default_device = g_ptr_array_index (devices, 0);
				non_default_ac = candidate;
			}
		}
	}

	/* Prefer the default connection if one exists, otherwise return the first
	 * non-default connection.
	 */
	if (!default_ac && non_default_ac) {
		default_ac = non_default_ac;
		*device = non_default_device;
	}
	return default_ac;
}

/* Find a device to activate the connection on.
 * IN:  connection:  connection to activate
 *      iface:       device interface name to use (optional)
 *      ap:          access point to use (optional; valid just for 802-11-wireless)
 * OUT: device:      found device
 *      spec_object: specific_object path of NMAccessPoint
 * RETURNS: TRUE when a device is found, FALSE otherwise.
 */
static gboolean
find_device_for_connection (NmCli *nmc, NMConnection *connection, const char *iface, const char *ap,
                            NMDevice **device, const char **spec_object, GError **error)
{
	NMSettingConnection *s_con;
	const char *con_type;
	int i, j;

	g_return_val_if_fail (nmc != NULL, FALSE);
	g_return_val_if_fail (device != NULL && *device == NULL, FALSE);
	g_return_val_if_fail (spec_object != NULL && *spec_object == NULL, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	g_assert (s_con);
	con_type = nm_setting_connection_get_connection_type (s_con);

	if (strcmp (con_type, "vpn") == 0) {
		/* VPN connections */
		NMActiveConnection *active = NULL;
		if (iface) {
			const GPtrArray *connections = nm_client_get_active_connections (nmc->client);
			for (i = 0; connections && (i < connections->len) && !active; i++) {
				NMActiveConnection *candidate = g_ptr_array_index (connections, i);
				const GPtrArray *devices = nm_active_connection_get_devices (candidate);
				if (!devices || !devices->len)
					continue;

				for (j = 0; devices && (j < devices->len); j++) {
					NMDevice *dev = g_ptr_array_index (devices, j);
					if (!strcmp (iface, nm_device_get_iface (dev))) {
						active = candidate;
						*device = dev;
						break;
					}
				}
			}
			if (!active) {
				g_set_error (error, 0, 0, _("no active connection on device '%s'"), iface);
				return FALSE;
			}
			*spec_object = nm_object_get_path (NM_OBJECT (active));
			return TRUE;
		} else {
			active = get_default_active_connection (nmc, device);
			if (!active) {
				g_set_error (error, 0, 0, _("no active connection or device"));
				return FALSE;
			}
			*spec_object = nm_object_get_path (NM_OBJECT (active));
			return TRUE;
		}
	} else {
		/* Other connections */
		NMDevice *found_device = NULL;
		const GPtrArray *devices = nm_client_get_devices (nmc->client);

		for (i = 0; devices && (i < devices->len) && !found_device; i++) {
			NMDevice *dev = g_ptr_array_index (devices, i);

			if (iface) {
				const char *dev_iface = nm_device_get_iface (dev);
				if (   !strcmp (dev_iface, iface)
				    && nm_device_is_connection_compatible (dev, connection, NULL)) {
					found_device = dev;
				}
			} else {
				if (nm_device_is_connection_compatible (dev, connection, NULL)) {
					found_device = dev;
				}
			}

			if (found_device && ap && !strcmp (con_type, "802-11-wireless") && NM_IS_DEVICE_WIFI (dev)) {
				char *hwaddr_up = g_ascii_strup (ap, -1);
				const GPtrArray *aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (dev));
				found_device = NULL;  /* Mark as not found; set to the device again later, only if AP matches */

				for (j = 0; aps && (j < aps->len); j++) {
					NMAccessPoint *candidate_ap = g_ptr_array_index (aps, j);
					const char *candidate_hwaddr = nm_access_point_get_hw_address (candidate_ap);

					if (!strcmp (hwaddr_up, candidate_hwaddr)) {
						found_device = dev;
						*spec_object = nm_object_get_path (NM_OBJECT (candidate_ap));
						break;
					}
				}
				g_free (hwaddr_up);
			}
		}

		if (found_device) {
			*device = found_device;
			return TRUE;
		} else {
			if (iface)
				g_set_error (error, 0, 0, _("device '%s' not compatible with connection '%s'"), iface, nm_setting_connection_get_id (s_con));
			else
				g_set_error (error, 0, 0, _("no device found for connection '%s'"), nm_setting_connection_get_id (s_con));
			return FALSE;
		}
	}
}

static const char *
active_connection_state_to_string (NMActiveConnectionState state)
{
	switch (state) {
	case NM_ACTIVE_CONNECTION_STATE_ACTIVATING:
		return _("activating");
	case NM_ACTIVE_CONNECTION_STATE_ACTIVATED:
		return _("activated");
	case NM_ACTIVE_CONNECTION_STATE_UNKNOWN:
	default:
		return _("unknown");
	}
}

static const char *
vpn_connection_state_to_string (NMVPNConnectionState state)
{
	switch (state) {
	case NM_VPN_CONNECTION_STATE_PREPARE:
		return _("VPN connecting (prepare)");
	case NM_VPN_CONNECTION_STATE_NEED_AUTH:
		return _("VPN connecting (need authentication)");
	case NM_VPN_CONNECTION_STATE_CONNECT:
		return _("VPN connecting");
	case NM_VPN_CONNECTION_STATE_IP_CONFIG_GET:
		return _("VPN connecting (getting IP configuration)");
	case NM_VPN_CONNECTION_STATE_ACTIVATED:
		return _("VPN connected");
	case NM_VPN_CONNECTION_STATE_FAILED:
		return _("VPN connection failed");
	case NM_VPN_CONNECTION_STATE_DISCONNECTED:
		return _("VPN disconnected");
	default:
		return _("unknown");
	}
}

static const char *
vpn_connection_state_reason_to_string (NMVPNConnectionStateReason reason)
{
	switch (reason) {
	case NM_VPN_CONNECTION_STATE_REASON_UNKNOWN:
		return _("unknown reason");
	case NM_VPN_CONNECTION_STATE_REASON_NONE:
		return _("none");
	case NM_VPN_CONNECTION_STATE_REASON_USER_DISCONNECTED:
		return _("the user was disconnected");
	case NM_VPN_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED:
		return _("the base network connection was interrupted");
	case NM_VPN_CONNECTION_STATE_REASON_SERVICE_STOPPED:
		return _("the VPN service stopped unexpectedly");
	case NM_VPN_CONNECTION_STATE_REASON_IP_CONFIG_INVALID:
		return _("the VPN service returned invalid configuration");
	case NM_VPN_CONNECTION_STATE_REASON_CONNECT_TIMEOUT:
		return _("the connection attempt timed out");
	case NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT:
		return _("the VPN service did not start in time");
	case NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_FAILED:
		return _("the VPN service failed to start");
	case NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS:
		return _("no valid VPN secrets");
	case NM_VPN_CONNECTION_STATE_REASON_LOGIN_FAILED:
		return _("invalid VPN secrets");
	case NM_VPN_CONNECTION_STATE_REASON_CONNECTION_REMOVED:
		return _("the connection was removed");
	default:
		return _("unknown");
	}
}

static void
active_connection_state_cb (NMActiveConnection *active, GParamSpec *pspec, gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;
	NMActiveConnectionState state;

	state = nm_active_connection_get_state (active);

	printf (_("state: %s\n"), active_connection_state_to_string (state));

	if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
		printf (_("Connection activated\n"));
		quit ();
	} else if (state == NM_ACTIVE_CONNECTION_STATE_UNKNOWN) {
		g_string_printf (nmc->return_text, _("Error: Connection activation failed."));
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		quit ();
	}
}

static void
vpn_connection_state_cb (NMVPNConnection *vpn,
                         NMVPNConnectionState state,
                         NMVPNConnectionStateReason reason,
                         gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;

	switch (state) {
	case NM_VPN_CONNECTION_STATE_PREPARE:
	case NM_VPN_CONNECTION_STATE_NEED_AUTH:
	case NM_VPN_CONNECTION_STATE_CONNECT:
	case NM_VPN_CONNECTION_STATE_IP_CONFIG_GET:
		printf (_("state: %s (%d)\n"), vpn_connection_state_to_string (state), state);
		break;

	case NM_VPN_CONNECTION_STATE_ACTIVATED:
		printf (_("Connection activated\n"));
		quit ();
		break;

	case NM_VPN_CONNECTION_STATE_FAILED:
	case NM_VPN_CONNECTION_STATE_DISCONNECTED:
		g_string_printf (nmc->return_text, _("Error: Connection activation failed: %s."), vpn_connection_state_reason_to_string (reason));
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		quit ();
		break;

	default:
		break;
	}
}

static gboolean
timeout_cb (gpointer user_data)
{
	/* Time expired -> exit nmcli */

	NmCli *nmc = (NmCli *) user_data;

	g_string_printf (nmc->return_text, _("Error: Timeout %d sec expired."), nmc->timeout);
	nmc->return_value = NMC_RESULT_ERROR_TIMEOUT_EXPIRED;
	quit ();
	return FALSE;
}

static void
foo_active_connections_changed_cb (NMClient *client,
                                   GParamSpec *pspec,
                                   gpointer user_data)
{
	/* Call again activate_connection_cb with dummy arguments;
	 * the correct ones are taken from its first call.
	 */
	activate_connection_cb (NULL, NULL, NULL);
}

static void
activate_connection_cb (gpointer user_data, const char *path, GError *error)
{
	NmCli *nmc = (NmCli *) user_data;
	NMActiveConnection *active;
	NMActiveConnectionState state;
	static gulong handler_id = 0;
	static NmCli *orig_nmc;
	static const char *orig_path;
	static GError *orig_error;

	if (nmc)
	{
		/* Called first time; store actual arguments */
		orig_nmc = nmc;
		orig_path = path;
		orig_error = error;
	}

	/* Disconnect the handler not to be run any more */
	if (handler_id != 0) {
		g_signal_handler_disconnect (orig_nmc->client, handler_id);
		handler_id = 0;
	}

	if (orig_error) {
		g_string_printf (orig_nmc->return_text, _("Error: Connection activation failed: %s"), orig_error->message);
		orig_nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		quit ();
	} else {
		active = nm_client_get_active_connection_by_path (orig_nmc->client, orig_path);
		if (!active) {
			/* The active connection path is not in active connections list yet; wait for active-connections signal. */
			/* This is basically the case for VPN connections. */
			if (nmc) {
				/* Called first time, i.e. by nm_client_activate_connection() */
				handler_id = g_signal_connect (orig_nmc->client, "notify::active-connections",
				                               G_CALLBACK (foo_active_connections_changed_cb), NULL);
				return;
			} else {
				g_string_printf (orig_nmc->return_text, _("Error: Obtaining active connection for '%s' failed."), orig_path);
				orig_nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
				quit ();
				return;
			}
		}

		state = nm_active_connection_get_state (active);

		printf (_("Active connection state: %s\n"), active_connection_state_to_string (state));
		printf (_("Active connection path: %s\n"), orig_path);

		if (orig_nmc->nowait_flag || state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
			/* don't want to wait or already activated */
			quit ();
		} else {
			if (NM_IS_VPN_CONNECTION (active))
				g_signal_connect (NM_VPN_CONNECTION (active), "vpn-state-changed", G_CALLBACK (vpn_connection_state_cb), orig_nmc);
			else
				g_signal_connect (active, "notify::state", G_CALLBACK (active_connection_state_cb), orig_nmc);

			/* Start timer not to loop forever when signals are not emitted */
			g_timeout_add_seconds (orig_nmc->timeout, timeout_cb, orig_nmc);
		}
	}
}

static NMCResultCode
do_connection_up (NmCli *nmc, int argc, char **argv)
{
	NMDevice *device = NULL;
	const char *spec_object = NULL;
	gboolean device_found;
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	gboolean is_system;
	const char *con_path;
	const char *con_type;
	const char *iface = NULL;
	const char *ap = NULL;
	gboolean id_specified = FALSE;
	gboolean wait = TRUE;
	GError *error = NULL;

	/* Set default timeout for connection activation. It can take quite a long time.
	 * Using 90 seconds.
	 */
	nmc->timeout = 90;

	while (argc > 0) {
		if (strcmp (*argv, "id") == 0 || strcmp (*argv, "uuid") == 0) {
			const char *selector = *argv;
			id_specified = TRUE;

			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}

			if ((connection = find_connection (nmc->system_connections, selector, *argv)) == NULL)
				connection = find_connection (nmc->user_connections, selector, *argv);

			if (!connection) {
				g_string_printf (nmc->return_text, _("Error: Unknown connection: %s."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
				goto error;
			}
		}
		else if (strcmp (*argv, "iface") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}

			iface = *argv;
		}
		else if (strcmp (*argv, "ap") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}

			ap = *argv;
		}
		else if (strcmp (*argv, "--nowait") == 0) {
			wait = FALSE;
		} else if (strcmp (*argv, "--timeout") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}

			errno = 0;
			nmc->timeout = strtol (*argv, NULL, 10);
			if (errno || nmc->timeout < 0) {
				g_string_printf (nmc->return_text, _("Error: timeout value '%s' is not valid."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
		} else {
			fprintf (stderr, _("Unknown parameter: %s\n"), *argv);
		}

		argc--;
		argv++;
	}

	if (!id_specified) {
		g_string_printf (nmc->return_text, _("Error: id or uuid has to be specified."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}

	/* create NMClient */
	if (!nmc->get_client (nmc))
		goto error;

	is_system = (nm_connection_get_scope (connection) == NM_CONNECTION_SCOPE_SYSTEM) ? TRUE : FALSE;
	con_path = nm_connection_get_path (connection);

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	g_assert (s_con);
	con_type = nm_setting_connection_get_connection_type (s_con);

	device_found = find_device_for_connection (nmc, connection, iface, ap, &device, &spec_object, &error);

	if (!device_found) {
		if (error)
			g_string_printf (nmc->return_text, _("Error: No suitable device found: %s."), error->message);
		else
			g_string_printf (nmc->return_text, _("Error: No suitable device found."));
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		goto error;
	}

	/* Use nowait_flag instead of should_wait because exitting has to be postponed till active_connection_state_cb()
	 * is called, giving NM time to check our permissions */
	nmc->nowait_flag = !wait;
	nmc->should_wait = TRUE;
	nm_client_activate_connection (nmc->client,
	                               is_system ? NM_DBUS_SERVICE_SYSTEM_SETTINGS : NM_DBUS_SERVICE_USER_SETTINGS,
	                               con_path,
	                               device,
	                               spec_object,
	                               activate_connection_cb,
	                               nmc);

	return nmc->return_value;
error:
	nmc->should_wait = FALSE;
	return nmc->return_value;
}

static NMCResultCode
do_connection_down (NmCli *nmc, int argc, char **argv)
{
	NMConnection *connection = NULL;
	NMActiveConnection *active = NULL;
	const GPtrArray *active_cons;
	const char *con_path;
	const char *active_path;
	NMConnectionScope active_service_scope, con_scope;
	gboolean id_specified = FALSE;
	gboolean wait = TRUE;
	int i;

	while (argc > 0) {
		if (strcmp (*argv, "id") == 0 || strcmp (*argv, "uuid") == 0) {
			const char *selector = *argv;
			id_specified = TRUE;

			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}

			if ((connection = find_connection (nmc->system_connections, selector, *argv)) == NULL)
				connection = find_connection (nmc->user_connections, selector, *argv);

			if (!connection) {
				g_string_printf (nmc->return_text, _("Error: Unknown connection: %s."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
				goto error;
			}
		}
		else if (strcmp (*argv, "--nowait") == 0) {
			wait = FALSE;
		}
		else {
			fprintf (stderr, _("Unknown parameter: %s\n"), *argv);
		}

		argc--;
		argv++;
	}

	if (!id_specified) {
		g_string_printf (nmc->return_text, _("Error: id or uuid has to be specified."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}

	/* create NMClient */
	if (!nmc->get_client (nmc))
		goto error;

	con_path = nm_connection_get_path (connection);
	con_scope = nm_connection_get_scope (connection);

	active_cons = nm_client_get_active_connections (nmc->client);
	for (i = 0; active_cons && (i < active_cons->len); i++) {
		NMActiveConnection *candidate = g_ptr_array_index (active_cons, i);

		active_path = nm_active_connection_get_connection (candidate);
		active_service_scope = nm_active_connection_get_scope (candidate);
		if (!strcmp (active_path, con_path) && active_service_scope == con_scope) {
			active = candidate;
			break;
		}
	}

	if (active)
		nm_client_deactivate_connection (nmc->client, active);
	else {
		fprintf (stderr, _("Warning: Connection not active\n"));
	}
	sleep (1);  /* Don't quit immediatelly and give NM time to check our permissions */

error:
	nmc->should_wait = FALSE;
	return nmc->return_value;
}

/* callback called when connections are obtained from the settings service */
static void
get_connections_cb (NMSettingsInterface *settings, gpointer user_data)
{
	ArgsInfo *args = (ArgsInfo *) user_data;
	static gboolean system_cb_called = FALSE;
	static gboolean user_cb_called = FALSE;
	GError *error = NULL;

	if (NM_IS_REMOTE_SETTINGS_SYSTEM (settings)) {
		system_cb_called = TRUE;
		args->nmc->system_connections = nm_settings_interface_list_connections (settings);
	}
	else {
		user_cb_called = TRUE;
		args->nmc->user_connections = nm_settings_interface_list_connections (settings);
	}

	/* return and wait for the callback of the second settings is called */
	if (   (args->nmc->system_settings_running && !system_cb_called)
	    || (args->nmc->user_settings_running && !user_cb_called))
		return;

	if (args->argc == 0) {
		if (!nmc_terse_option_check (args->nmc->print_output, args->nmc->required_fields, &error))
			goto opt_error;
		args->nmc->return_value = do_connections_list (args->nmc, args->argc, args->argv);
	} else {

	 	if (matches (*args->argv, "list") == 0) {
			args->nmc->return_value = do_connections_list (args->nmc, args->argc-1, args->argv+1);
		}
		else if (matches(*args->argv, "status") == 0) {
			if (!nmc_terse_option_check (args->nmc->print_output, args->nmc->required_fields, &error))
				goto opt_error;
			args->nmc->return_value = do_connections_status (args->nmc, args->argc-1, args->argv+1);
		}
		else if (matches(*args->argv, "up") == 0) {
			args->nmc->return_value = do_connection_up (args->nmc, args->argc-1, args->argv+1);
		}
		else if (matches(*args->argv, "down") == 0) {
			args->nmc->return_value = do_connection_down (args->nmc, args->argc-1, args->argv+1);
		}
		else if (matches (*args->argv, "help") == 0) {
			usage ();
			args->nmc->should_wait = FALSE;
		} else {
			usage ();
			g_string_printf (args->nmc->return_text, _("Error: 'con' command '%s' is not valid."), *args->argv);
			args->nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			args->nmc->should_wait = FALSE;
		}
	}

	if (!args->nmc->should_wait)
		quit ();
	return;

opt_error:
	g_string_printf (args->nmc->return_text, _("Error: %s."), error->message);
	args->nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
	args->nmc->should_wait = FALSE;
	g_error_free (error);
	quit ();
	return;
}


/* Entry point function for connections-related commands: 'nmcli con' */
NMCResultCode
do_connections (NmCli *nmc, int argc, char **argv)
{
	DBusGConnection *bus;
	GError *error = NULL;

	nmc->should_wait = TRUE;

	args_info.nmc = nmc;
	args_info.argc = argc;
	args_info.argv = argv;

	/* connect to DBus' system bus */
	bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
	if (error || !bus) {
		g_string_printf (nmc->return_text, _("Error: could not connect to D-Bus."));
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		return nmc->return_value;
	}

	/* get system settings */
	if (!(nmc->system_settings = nm_remote_settings_system_new (bus))) {
		g_string_printf (nmc->return_text, _("Error: Could not get system settings."));
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		return nmc->return_value;

	}

	/* get user settings */
	if (!(nmc->user_settings = nm_remote_settings_new (bus, NM_CONNECTION_SCOPE_USER))) {
		g_string_printf (nmc->return_text, _("Error: Could not get user settings."));
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		return nmc->return_value;
	}

	/* find out whether setting services are running */
	g_object_get (nmc->system_settings, NM_REMOTE_SETTINGS_SERVICE_RUNNING, &nmc->system_settings_running, NULL);
	g_object_get (nmc->user_settings, NM_REMOTE_SETTINGS_SERVICE_RUNNING, &nmc->user_settings_running, NULL);

	if (!nmc->system_settings_running && !nmc->user_settings_running) {
		g_string_printf (nmc->return_text, _("Error: Can't obtain connections: settings services are not running."));
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		return nmc->return_value;
	}

	/* connect to signal "connections-read" - emitted when connections are fetched and ready */
	if (nmc->system_settings_running)
		g_signal_connect (nmc->system_settings, NM_SETTINGS_INTERFACE_CONNECTIONS_READ,
		                  G_CALLBACK (get_connections_cb), &args_info);

	if (nmc->user_settings_running)
		g_signal_connect (nmc->user_settings, NM_SETTINGS_INTERFACE_CONNECTIONS_READ,
		                  G_CALLBACK (get_connections_cb), &args_info);

	dbus_g_connection_unref (bus);

	/* The rest will be done in get_connection_cb() callback.
	 * We need to wait for signals that connections are read.
	 */
	return NMC_RESULT_SUCCESS;
}
