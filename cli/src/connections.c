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
 * (C) Copyright 2010 - 2012 Red Hat, Inc.
 */

#include "config.h"

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
#include <nm-device-ethernet.h>
#include <nm-device-wifi.h>
#if WITH_WIMAX
#include <nm-device-wimax.h>
#endif
#include <nm-device-modem.h>
#include <nm-device-bt.h>
#include <nm-device-olpc-mesh.h>
#include <nm-device-infiniband.h>
#include <nm-device-bond.h>
#include <nm-device-vlan.h>
#include <nm-remote-settings.h>
#include <nm-vpn-connection.h>
#include <nm-utils.h>

#include "utils.h"
#include "common.h"
#include "settings.h"
#include "connections.h"


/* Available fields for 'con list' */
static NmcOutputField nmc_fields_con_list[] = {
	{"NAME",            N_("NAME"),           25, NULL, 0},  /* 0 */
	{"UUID",            N_("UUID"),           38, NULL, 0},  /* 1 */
	{"TYPE",            N_("TYPE"),           17, NULL, 0},  /* 2 */
	{"TIMESTAMP",       N_("TIMESTAMP"),      12, NULL, 0},  /* 3 */
	{"TIMESTAMP-REAL",  N_("TIMESTAMP-REAL"), 34, NULL, 0},  /* 4 */
	{"AUTOCONNECT",     N_("AUTOCONNECT"),    13, NULL, 0},  /* 5 */
	{"READONLY",        N_("READONLY"),       10, NULL, 0},  /* 6 */
	{"DBUS-PATH",       N_("DBUS-PATH"),      42, NULL, 0},  /* 7 */
	{NULL,              NULL,                  0, NULL, 0}
};
#define NMC_FIELDS_CON_LIST_ALL     "NAME,UUID,TYPE,TIMESTAMP,TIMESTAMP-REAL,AUTOCONNECT,READONLY,DBUS-PATH"
#define NMC_FIELDS_CON_LIST_COMMON  "NAME,UUID,TYPE,TIMESTAMP-REAL"

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
	SETTING_FIELD (NM_SETTING_WIMAX_SETTING_NAME, 0),                 /* 15 */
	SETTING_FIELD (NM_SETTING_INFINIBAND_SETTING_NAME, 0),            /* 16 */
	SETTING_FIELD (NM_SETTING_BOND_SETTING_NAME, 0),                  /* 17 */
	SETTING_FIELD (NM_SETTING_VLAN_SETTING_NAME, 0),                  /* 18 */
	{NULL, NULL, 0, NULL, 0}
};
#define NMC_FIELDS_SETTINGS_NAMES_ALL_X  NM_SETTING_CONNECTION_SETTING_NAME","\
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
                                         NM_SETTING_VPN_SETTING_NAME","\
                                         NM_SETTING_INFINIBAND_SETTING_NAME","\
                                         NM_SETTING_BOND_SETTING_NAME","\
                                         NM_SETTING_VLAN_SETTING_NAME
#if WITH_WIMAX
#define NMC_FIELDS_SETTINGS_NAMES_ALL    NMC_FIELDS_SETTINGS_NAMES_ALL_X","\
                                         NM_SETTING_WIMAX_SETTING_NAME
#else
#define NMC_FIELDS_SETTINGS_NAMES_ALL    NMC_FIELDS_SETTINGS_NAMES_ALL_X
#endif


/* Available fields for 'con status' */
static NmcOutputField nmc_fields_con_status[] = {
	{"GROUP",         N_("GROUP"),         9, NULL, 0},  /* 0 */  /* used only for 'GENERAL' group listing */
	{"NAME",          N_("NAME"),         25, NULL, 0},  /* 1 */
	{"UUID",          N_("UUID"),         38, NULL, 0},  /* 2 */
	{"DEVICES",       N_("DEVICES"),      10, NULL, 0},  /* 3 */
	{"STATE",         N_("STATE"),        12, NULL, 0},  /* 4 */
	{"DEFAULT",       N_("DEFAULT"),       8, NULL, 0},  /* 5 */
	{"DEFAULT6",      N_("DEFAULT6"),      9, NULL, 0},  /* 6 */
	{"SPEC-OBJECT",   N_("SPEC-OBJECT"),  10, NULL, 0},  /* 7 */
	{"VPN",           N_("VPN"),           5, NULL, 0},  /* 8 */
	{"DBUS-PATH",     N_("DBUS-PATH"),    51, NULL, 0},  /* 9 */
	{"CON-PATH",      N_("CON-PATH"),     44, NULL, 0},  /* 10 */
	{"ZONE",          N_("ZONE"),         15, NULL, 0},  /* 11 */
	{"MASTER-PATH",   N_("MASTER-PATH"),  44, NULL, 0},  /* 12 */
	{NULL,            NULL,                0, NULL, 0}
};
#define NMC_FIELDS_CON_STATUS_ALL     "NAME,UUID,DEVICES,STATE,DEFAULT,DEFAULT6,VPN,ZONE,DBUS-PATH,CON-PATH,SPEC-OBJECT,MASTER-PATH"
#define NMC_FIELDS_CON_STATUS_COMMON  "NAME,UUID,DEVICES,DEFAULT,VPN,MASTER-PATH"

/* Available fields for 'con status id/uuid/path <con>' */
static NmcOutputField nmc_fields_status_details_groups[] = {
	{"GENERAL",  N_("GENERAL"), 9, NULL, 0},  /* 0 */
	{"IP",       N_("IP"),      5, NULL, 0},  /* 1 */
	{"VPN",      N_("VPN"),     5, NULL, 0},  /* 2 */
	{NULL, NULL, 0, NULL, 0}
};
#define NMC_FIELDS_CON_STATUS_DETAILS_ALL  "GENERAL,IP,VPN"

/* GENERAL group is the same as nmc_fields_con_status */
#define NMC_FIELDS_CON_STATUS_DETAILS_GENERAL_ALL  "GROUP,"NMC_FIELDS_CON_STATUS_ALL

/* IP group is handled by common.c */

/* Available fields for VPN group */
static NmcOutputField nmc_fields_status_details_vpn[] = {
	{"GROUP",     N_("GROUP"),       9, NULL, 0},  /* 0 */
	{"TYPE",      N_("TYPE"),       15, NULL, 0},  /* 1 */
	{"USERNAME",  N_("USERNAME"),   15, NULL, 0},  /* 2 */
	{"GATEWAY",   N_("GATEWAY"),    25, NULL, 0},  /* 3 */
	{"BANNER",    N_("BANNER"),    120, NULL, 0},  /* 4 */
	{"VPN-STATE", N_("VPN-STATE"),  40, NULL, 0},  /* 5 */
	{"CFG",       N_("CFG"),       120, NULL, 0},  /* 6 */
	{NULL, NULL, 0, NULL, 0}
};
#define NMC_FIELDS_CON_STATUS_DETAILS_VPN_ALL  "GROUP,TYPE,USERNAME,GATEWAY,BANNER,VPN-STATE,CFG"


typedef struct {
	NmCli *nmc;
	int argc;
	char **argv;
} ArgsInfo;

/* glib main loop variable - defined in nmcli.c */
extern GMainLoop *loop;

static ArgsInfo args_info;

static void
usage (void)
{
	fprintf (stderr,
	         _("Usage: nmcli con { COMMAND | help }\n"
	         "  COMMAND := { list | status | up | down | delete }\n\n"
	         "  list [id <id> | uuid <id>]\n"
	         "  status [id <id> | uuid <id> | path <path>]\n"
#if WITH_WIMAX
	         "  up id <id> | uuid <id> [iface <iface>] [ap <BSSID>] [nsp <name>] [--nowait] [--timeout <timeout>]\n"
#else
	         "  up id <id> | uuid <id> [iface <iface>] [ap <BSSID>] [--nowait] [--timeout <timeout>]\n"
#endif
	         "  down id <id> | uuid <id>\n"
	         "  delete id <id> | uuid <id>\n"));
}

/* The real commands that do something - i.e. not 'help', etc. */
static const char *real_con_commands[] = {
	"list",
	"status",
	"up",
	"down",
	"delete",
	NULL
};

/* quit main loop */
static void
quit (void)
{
	g_main_loop_quit (loop);  /* quit main loop */
}

static gboolean
nmc_connection_detail (NMConnection *connection, NmCli *nmc)
{
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
			NMSettingConnection *s_con = nm_connection_get_setting_connection (connection);
			if (s_con) {
				setting_connection_details (s_con, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[1].name)) {
			NMSettingWired *s_wired = nm_connection_get_setting_wired (connection);
			if (s_wired) {
				setting_wired_details (s_wired, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[2].name)) {
			NMSetting8021x *s_8021X = nm_connection_get_setting_802_1x (connection);
			if (s_8021X) {
				setting_802_1X_details (s_8021X, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[3].name)) {
			NMSettingWireless *s_wireless = nm_connection_get_setting_wireless (connection);
			if (s_wireless) {
				setting_wireless_details (s_wireless, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[4].name)) {
			NMSettingWirelessSecurity *s_wsec = nm_connection_get_setting_wireless_security (connection);
			if (s_wsec) {
				setting_wireless_security_details (s_wsec, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[5].name)) {
			NMSettingIP4Config *s_ip4 = nm_connection_get_setting_ip4_config (connection);
			if (s_ip4) {
				setting_ip4_config_details (s_ip4, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[6].name)) {
			NMSettingIP6Config *s_ip6 = nm_connection_get_setting_ip6_config (connection);
			if (s_ip6) {
				setting_ip6_config_details (s_ip6, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[7].name)) {
			NMSettingSerial *s_serial = nm_connection_get_setting_serial (connection);
			if (s_serial) {
				setting_serial_details (s_serial, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[8].name)) {
			NMSettingPPP *s_ppp = nm_connection_get_setting_ppp (connection);
			if (s_ppp) {
				setting_ppp_details (s_ppp, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[9].name)) {
			NMSettingPPPOE *s_pppoe = nm_connection_get_setting_pppoe (connection);
			if (s_pppoe) {
				setting_pppoe_details (s_pppoe, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[10].name)) {
			NMSettingGsm *s_gsm = nm_connection_get_setting_gsm (connection);
			if (s_gsm) {
				setting_gsm_details (s_gsm, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[11].name)) {
			NMSettingCdma *s_cdma = nm_connection_get_setting_cdma (connection);
			if (s_cdma) {
				setting_cdma_details (s_cdma, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[12].name)) {
			NMSettingBluetooth *s_bluetooth = nm_connection_get_setting_bluetooth (connection);
			if (s_bluetooth) {
				setting_bluetooth_details (s_bluetooth, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[13].name)) {
			NMSettingOlpcMesh *s_olpc_mesh = nm_connection_get_setting_olpc_mesh (connection);
			if (s_olpc_mesh) {
				setting_olpc_mesh_details (s_olpc_mesh, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[14].name)) {
			NMSettingVPN *s_vpn = nm_connection_get_setting_vpn (connection);
			if (s_vpn) {
				setting_vpn_details (s_vpn, nmc);
				was_output = TRUE;
				continue;
			}
		}

#if WITH_WIMAX
		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[15].name)) {
			NMSettingWimax *s_wimax = nm_connection_get_setting_wimax (connection);
			if (s_wimax) {
				setting_wimax_details (s_wimax, nmc);
				was_output = TRUE;
				continue;
			}
		}
#endif

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[16].name)) {
			NMSettingInfiniband *s_infiniband = nm_connection_get_setting_infiniband (connection);
			if (s_infiniband) {
				setting_infiniband_details (s_infiniband, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[17].name)) {
			NMSettingBond *s_bond = nm_connection_get_setting_bond (connection);
			if (s_bond) {
				setting_bond_details (s_bond, nmc);
				was_output = TRUE;
				continue;
			}
		}

		if (!strcasecmp (nmc_fields_settings_names[section_idx].name, nmc_fields_settings_names[18].name)) {
			NMSettingVlan *s_vlan = nm_connection_get_setting_vlan (connection);
			if (s_vlan) {
				setting_vlan_details (s_vlan, nmc);
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
	time_t timestamp_real;
	char *timestamp_str;
	char timestamp_real_str[64];

	s_con = nm_connection_get_setting_connection (connection);
	if (s_con) {
		/* Obtain field values */
		timestamp = nm_setting_connection_get_timestamp (s_con);
		timestamp_str = g_strdup_printf ("%" G_GUINT64_FORMAT, timestamp);
		timestamp_real = timestamp;
		strftime (timestamp_real_str, sizeof (timestamp_real_str), "%c", localtime (&timestamp_real));

		nmc->allowed_fields[0].value = nm_setting_connection_get_id (s_con);
		nmc->allowed_fields[1].value = nm_setting_connection_get_uuid (s_con);
		nmc->allowed_fields[2].value = nm_setting_connection_get_connection_type (s_con);
		nmc->allowed_fields[3].value = timestamp_str;
		nmc->allowed_fields[4].value = timestamp ? timestamp_real_str : _("never");
		nmc->allowed_fields[5].value = nm_setting_connection_get_autoconnect (s_con) ? _("yes") : _("no");
		nmc->allowed_fields[6].value = nm_setting_connection_get_read_only (s_con) ? _("yes") : _("no");
		nmc->allowed_fields[7].value = nm_connection_get_path (connection);

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
		s_con = nm_connection_get_setting_connection (connection);
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

		/* Print headers */
		nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ADD | NMC_PF_FLAG_FIELD_NAMES;
		nmc->print_fields.header_name = _("Connection list");
		print_fields (nmc->print_fields, nmc->allowed_fields);

		/* Print values */
		g_slist_foreach (nmc->system_connections, (GFunc) show_connection, nmc);
	}
	else {
		while (argc > 0) {
			if (strcmp (*argv, "id") == 0 || strcmp (*argv, "uuid") == 0) {
				const char *selector = *argv;
				NMConnection *con;

				if (next_arg (&argc, &argv) != 0) {
					g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					return nmc->return_value;
				}
				valid_param_specified = TRUE;
				if (!nmc->mode_specified)
					nmc->multiline_output = TRUE;  /* multiline mode is default for 'con list id|uuid' */

				con = find_connection (nmc->system_connections, selector, *argv);
				if (con) {
					nmc_connection_detail (con, nmc);
				}
				else {
					g_string_printf (nmc->return_text, _("Error: %s - no such connection."), *argv);
					nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
				}
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

static const char *
active_connection_state_to_string (NMActiveConnectionState state)
{
	switch (state) {
	case NM_ACTIVE_CONNECTION_STATE_ACTIVATING:
		return _("activating");
	case NM_ACTIVE_CONNECTION_STATE_ACTIVATED:
		return _("activated");
	case NM_ACTIVE_CONNECTION_STATE_DEACTIVATING:
		return _("deactivating");
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

static NMConnection *
get_connection_for_active (const GSList *con_list, NMActiveConnection *active)
{
	const GSList *iter;
	const char *path;

	path = nm_active_connection_get_connection (active);
	g_return_val_if_fail (path != NULL, NULL);

	for (iter = con_list; iter; iter = g_slist_next (iter)) {
		NMConnection *candidate = NM_CONNECTION (iter->data);

		if (strcmp (nm_connection_get_path (candidate), path) == 0)
			return candidate;
	}
	return NULL;
}

static gboolean
fill_in_fields_con_status (NMActiveConnection *active, GSList *con_list)
{
	GSList *iter;
	const char *active_path;
	NMSettingConnection *s_con;
	const GPtrArray *devices;
	GString *dev_str;
	NMActiveConnectionState state;
	int i;
	gboolean success = FALSE;

	active_path = nm_active_connection_get_connection (active);
	state = nm_active_connection_get_state (active);

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

	for (iter = con_list; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = (NMConnection *) iter->data;
		const char *con_path = nm_connection_get_path (connection);

		if (!strcmp (active_path, con_path)) {
			/* This connection is active */
			s_con = nm_connection_get_setting_connection (connection);
			g_assert (s_con != NULL);

			/* Fill field values */
			nmc_fields_con_status[0].value = nmc_fields_status_details_groups[0].name;
			nmc_fields_con_status[1].value = nm_setting_connection_get_id (s_con);
			nmc_fields_con_status[2].value = nm_setting_connection_get_uuid (s_con);
			nmc_fields_con_status[3].value = dev_str->str;
			nmc_fields_con_status[4].value = active_connection_state_to_string (state);
			nmc_fields_con_status[5].value = nm_active_connection_get_default (active) ? _("yes") : _("no");
			nmc_fields_con_status[6].value = nm_active_connection_get_default6 (active) ? _("yes") : _("no");
			nmc_fields_con_status[7].value = nm_active_connection_get_specific_object (active);
			nmc_fields_con_status[8].value = NM_IS_VPN_CONNECTION (active) ? _("yes") : _("no");
			nmc_fields_con_status[9].value = nm_object_get_path (NM_OBJECT (active));
			nmc_fields_con_status[10].value = nm_active_connection_get_connection (active);
			nmc_fields_con_status[11].value = nm_setting_connection_get_zone (s_con);
			nmc_fields_con_status[12].value = nm_active_connection_get_master (active);

			success = TRUE;
			break;
		}
	}

	/* Just free GString here, the char array has to be freed after printing
	 * (by free_fields_con_status()) */
	g_string_free (dev_str, FALSE);
	return success;
}

static void
free_fields_con_status (void)
{
	/* Just DEVICES string was dynamically allocated */
	g_free ((char *) nmc_fields_con_status[3].value);
	nmc_fields_con_status[3].value = NULL;
}

static void
show_active_connection (gpointer data, gpointer user_data)
{
	NMActiveConnection *active = NM_ACTIVE_CONNECTION (data);
	NmCli *nmc = (NmCli *) user_data;

	fill_in_fields_con_status (active, nmc->system_connections);

	nmc->print_fields.flags &= ~NMC_PF_FLAG_MAIN_HEADER_ADD & ~NMC_PF_FLAG_MAIN_HEADER_ONLY & ~NMC_PF_FLAG_FIELD_NAMES; /* Clear header flags */
	print_fields (nmc->print_fields, nmc->allowed_fields);

	free_fields_con_status ();
}

static NMActiveConnection *
find_active_connection (const GPtrArray *active_cons, const GSList *cons,
                        const char *filter_type, const char *filter_val)
{
	int i;
	const char *s_path, *a_path;
	const char *id;
	const char *uuid;
	NMConnection *con;
	NMSettingConnection *s_con;

	for (i = 0; active_cons && (i < active_cons->len); i++) {
		NMActiveConnection *candidate = g_ptr_array_index (active_cons, i);

		s_path = nm_active_connection_get_connection (candidate);
		a_path = nm_object_get_path (NM_OBJECT (candidate));
		uuid = nm_active_connection_get_uuid (candidate);

		con = get_connection_for_active (cons, candidate);
		s_con = nm_connection_get_setting_connection (con);
		g_assert (s_con != NULL);
		id = nm_setting_connection_get_id (s_con);

		if (filter_type) {
			if (   (strcmp (filter_type, "id") == 0 && strcmp (filter_val, id) == 0)
			    || (strcmp (filter_type, "uuid") == 0 && strcmp (filter_val, uuid) == 0)
			    || (strcmp (filter_type, "path") == 0 && strcmp (filter_val, s_path) == 0)
			    || (strcmp (filter_type, "path") == 0 && strcmp (filter_val, a_path) == 0)) {
				return candidate;
			}
		}
	}
	return NULL;
}

typedef struct {
	char **array;
	guint32 idx;
} FillVPNDataInfo;

static void
fill_vpn_data_item (const char *key, const char *value, gpointer user_data)
{
        FillVPNDataInfo *info = (FillVPNDataInfo *) user_data;

	info->array[info->idx++] = g_strdup_printf ("%s = %s", key, value);
}

// FIXME: The same or similar code for VPN info appears also in nm-applet (applet-dialogs.c),
// and in gnome-control-center as well. It could probably be shared somehow.
static char *
get_vpn_connection_type (NMConnection *connection)
{
	const char *type, *p;

	/* The service type is in form of "org.freedesktop.NetworkManager.vpnc".
	 * Extract end part after last dot, e.g. "vpnc"
	 */
	type = nm_setting_vpn_get_service_type (nm_connection_get_setting_vpn (connection));
	p = strrchr (type, '.');
	return g_strdup (p ? p + 1 : type);
}

/* VPN parameters can be found at:
 * http://git.gnome.org/browse/network-manager-openvpn/tree/src/nm-openvpn-service.h
 * http://git.gnome.org/browse/network-manager-vpnc/tree/src/nm-vpnc-service.h
 * http://git.gnome.org/browse/network-manager-pptp/tree/src/nm-pptp-service.h
 * http://git.gnome.org/browse/network-manager-openconnect/tree/src/nm-openconnect-service.h
 * http://git.gnome.org/browse/network-manager-openswan/tree/src/nm-openswan-service.h
 * See also 'properties' directory in these plugins.
 */
static const gchar *
find_vpn_gateway_key (const char *vpn_type)
{
	if (g_strcmp0 (vpn_type, "openvpn") == 0)     return "remote";
	if (g_strcmp0 (vpn_type, "vpnc") == 0)        return "IPSec gateway";
	if (g_strcmp0 (vpn_type, "pptp") == 0)        return "gateway";
	if (g_strcmp0 (vpn_type, "openconnect") == 0) return "gateway";
	if (g_strcmp0 (vpn_type, "openswan") == 0)    return "right";
	return "";
}

static const gchar *
find_vpn_username_key (const char *vpn_type)
{
	if (g_strcmp0 (vpn_type, "openvpn") == 0)     return "username";
	if (g_strcmp0 (vpn_type, "vpnc") == 0)        return "Xauth username";
	if (g_strcmp0 (vpn_type, "pptp") == 0)        return "user";
	if (g_strcmp0 (vpn_type, "openconnect") == 0) return "username";
	if (g_strcmp0 (vpn_type, "openswan") == 0)    return "leftxauthusername";
	return "";
}

enum VpnDataItem {
	VPN_DATA_ITEM_GATEWAY,
	VPN_DATA_ITEM_USERNAME
};

static const gchar *
get_vpn_data_item (NMConnection *connection, enum VpnDataItem vpn_data_item)
{
	const char *key;
	char *type = get_vpn_connection_type (connection);

	switch (vpn_data_item) {
	case VPN_DATA_ITEM_GATEWAY:
		key = find_vpn_gateway_key (type);
		break;
	case VPN_DATA_ITEM_USERNAME:
		key = find_vpn_username_key (type);
		break;
	default:
		key = "";
		break;
	}
	g_free (type);

	return nm_setting_vpn_get_data_item (nm_connection_get_setting_vpn (connection), key);
}
/* FIXME end */

static gboolean
nmc_active_connection_detail (NMActiveConnection *acon, NmCli *nmc)
{
	GError *error = NULL;
	GArray *print_groups;
	int i;
	char *fields_str;
	char *fields_all =    NMC_FIELDS_CON_STATUS_DETAILS_ALL;
	char *fields_common = NMC_FIELDS_CON_STATUS_DETAILS_ALL;
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

	print_groups = parse_output_fields (fields_str, nmc_fields_status_details_groups, &error);
	if (error) {
		if (error->code == 0)
			g_string_printf (nmc->return_text, _("Error: 'con status': %s"), error->message);
		else
			g_string_printf (nmc->return_text, _("Error: 'con status': %s; allowed fields: %s"), error->message, NMC_FIELDS_CON_STATUS_DETAILS_ALL);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return FALSE;
	}

	nmc->allowed_fields = nmc_fields_status_details_groups;
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ONLY;
	nmc->print_fields.header_name = _("Active connection details");
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_CON_STATUS_DETAILS_ALL, nmc->allowed_fields, NULL);
	print_fields (nmc->print_fields, nmc->allowed_fields);

	/* Loop through the groups and print them. */
	for (i = 0; i < print_groups->len; i++) {
		int group_idx = g_array_index (print_groups, int, i);

		if (nmc->print_output != NMC_PRINT_TERSE && !nmc->multiline_output && was_output)
			printf ("\n"); /* Empty line */

		was_output = FALSE;

		/* GENERAL */
		if (strcasecmp (nmc_fields_status_details_groups[group_idx].name, nmc_fields_status_details_groups[0].name) == 0) {
			nmc->allowed_fields = nmc_fields_con_status;
			nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_CON_STATUS_DETAILS_GENERAL_ALL, nmc->allowed_fields, NULL);

			/* Print field names */
			nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
			print_fields (nmc->print_fields, nmc->allowed_fields);

			/* Fill in values */
			fill_in_fields_con_status (acon, nmc->system_connections);

			/* and print them */
			nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
			print_fields (nmc->print_fields, nmc->allowed_fields);

			free_fields_con_status ();
			was_output = TRUE;
		}

		/* IP */
		if (strcasecmp (nmc_fields_status_details_groups[group_idx].name,  nmc_fields_status_details_groups[1].name) == 0) {
			const GPtrArray *devices;
			int j;

			devices = nm_active_connection_get_devices (acon);
			for (j = 0; devices && (j < devices->len); j++) {
				gboolean b1 = FALSE, b2 = FALSE, b3 = FALSE, b4 = FALSE;
				NMDevice *device = g_ptr_array_index (devices, j);
				NMIP4Config *cfg4 = nm_device_get_ip4_config (device);
				NMIP6Config *cfg6 = nm_device_get_ip6_config (device);
				NMDHCP4Config *dhcp4 = nm_device_get_dhcp4_config (device);
				NMDHCP6Config *dhcp6 = nm_device_get_dhcp6_config (device);

				b1 = print_ip4_config (cfg4, nmc, "IP4");
				b2 = print_dhcp4_config (dhcp4, nmc, "DHCP4");
				b3 = print_ip6_config (cfg6, nmc, "IP6");
				b4 = print_dhcp6_config (dhcp6, nmc, "DHCP6");
				was_output = was_output || b1 || b2 || b3 || b4;
			}
		}

		/* VPN */
		if (NM_IS_VPN_CONNECTION (acon) &&
		    strcasecmp (nmc_fields_status_details_groups[group_idx].name,  nmc_fields_status_details_groups[2].name) == 0) {
			NMConnection *con;
			NMSettingConnection *s_con;
			NMSettingVPN *s_vpn;
			NMVPNConnectionState vpn_state;
			char *type_str, *banner_str, *vpn_state_str;
			const char *username = NULL;
			char **vpn_data_array = NULL;
			guint32 items_num;

			con = get_connection_for_active (nmc->system_connections, acon);

			s_con = nm_connection_get_setting_connection (con);
			g_assert (s_con != NULL);

			nmc->allowed_fields = nmc_fields_status_details_vpn;
			nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_CON_STATUS_DETAILS_VPN_ALL, nmc->allowed_fields, NULL);

			/* Print field names */
			nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
			print_fields (nmc->print_fields, nmc->allowed_fields);

			s_vpn = nm_connection_get_setting_vpn (con);
			if (s_vpn) {
				items_num = nm_setting_vpn_get_num_data_items (s_vpn);
				if (items_num > 0) {
					FillVPNDataInfo info;

					vpn_data_array = g_new (char *, items_num + 1);
					info.array = vpn_data_array;
					info.idx = 0;
					nm_setting_vpn_foreach_data_item (s_vpn, &fill_vpn_data_item, &info);
					vpn_data_array[items_num] = NULL;
				}
				username = nm_setting_vpn_get_user_name (s_vpn);
			}

			type_str = get_vpn_connection_type (con);
			banner_str = g_strescape (nm_vpn_connection_get_banner (NM_VPN_CONNECTION (acon)), "");
			vpn_state = nm_vpn_connection_get_vpn_state (NM_VPN_CONNECTION (acon));
			vpn_state_str = g_strdup_printf ("%d - %s", vpn_state, vpn_connection_state_to_string (vpn_state));

			/* Print values */
			set_val_str (nmc->allowed_fields, 0, nmc_fields_status_details_groups[2].name);
			set_val_str (nmc->allowed_fields, 1, type_str);
			set_val_str (nmc->allowed_fields, 2, username ? username : get_vpn_data_item (con, VPN_DATA_ITEM_USERNAME));
			set_val_str (nmc->allowed_fields, 3, get_vpn_data_item (con, VPN_DATA_ITEM_GATEWAY));
			set_val_str (nmc->allowed_fields, 4, banner_str);
			set_val_str (nmc->allowed_fields, 5, vpn_state_str);
			set_val_arr (nmc->allowed_fields, 6, (const char **) vpn_data_array);

			nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
			print_fields (nmc->print_fields, nmc->allowed_fields);

			g_free (type_str);
			g_free (banner_str);
			g_free (vpn_state_str);
			g_strfreev (vpn_data_array);
			was_output = TRUE;
		}
	}

	if (print_groups)
		g_array_free (print_groups, FALSE);

	return TRUE;
}

static NMCResultCode
do_connections_status (NmCli *nmc, int argc, char **argv)
{
	const GPtrArray *active_cons;
	GError *err = NULL;
	GError *err1 = NULL;

	nmc->should_wait = FALSE;

	if (!nmc_is_nm_running (nmc, &err)) {
		if (err) {
			g_string_printf (nmc->return_text, _("Error: Can't find out if NetworkManager is running: %s."), err->message);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			g_error_free (err);
		} else {
			g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
			nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		}
		goto error;
	}

	/* Get active connections */
	nmc->get_client (nmc);
	active_cons = nm_client_get_active_connections (nmc->client);

	if (argc == 0) {
		char *fields_str;
		char *fields_all =    NMC_FIELDS_CON_STATUS_ALL;
		char *fields_common = NMC_FIELDS_CON_STATUS_COMMON;
		guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
		guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
		guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

		if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
			fields_str = fields_common;
		else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
			fields_str = fields_all;
		else
			fields_str = nmc->required_fields;

		nmc->allowed_fields = nmc_fields_con_status + 1 ;
		nmc->print_fields.indices = parse_output_fields (fields_str, nmc->allowed_fields, &err1);
		if (err1)
			goto error;

		/* Print headers */
		nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ADD | NMC_PF_FLAG_FIELD_NAMES;
		nmc->print_fields.header_name = _("Active connections");
		print_fields (nmc->print_fields, nmc->allowed_fields);

		if (active_cons && active_cons->len)
			g_ptr_array_foreach ((GPtrArray *) active_cons, show_active_connection, (gpointer) nmc);
	} else {
		while (argc > 0) {
			if (   strcmp (*argv, "id") == 0
			    || strcmp (*argv, "uuid") == 0
			    || strcmp (*argv, "path") == 0) {
				const char *selector = *argv;
				NMActiveConnection *acon;

				if (next_arg (&argc, &argv) != 0) {
					g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					return nmc->return_value;
				}
				if (!nmc->mode_specified)
					nmc->multiline_output = TRUE;  /* multiline mode is default for 'con status id|uuid|path' */

				acon = find_active_connection (active_cons, nmc->system_connections, selector, *argv);
				if (acon) {
					nmc_active_connection_detail (acon, nmc);
				} else {
					g_string_printf (nmc->return_text, _("Error: '%s' is not an active connection."), *argv);
					nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
				}
				break;
			} else {
				g_string_printf (nmc->return_text, _("Error: unknown parameter: %s"), *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			}

			argc--;
			argv++;
		}
	}

error:
	if (err1) {
		if (err1->code == 0)
			g_string_printf (nmc->return_text, _("Error: 'con status': %s"), err1->message);
		else
			g_string_printf (nmc->return_text, _("Error: 'con status': %s; allowed fields: %s"), err1->message, NMC_FIELDS_CON_STATUS_ALL);
		g_error_free (err1);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
	}
	return nmc->return_value;
}

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
 *      nsp:         Network Service Provider to use (option; valid only for wimax)
 * OUT: device:      found device
 *      spec_object: specific_object path of NMAccessPoint
 * RETURNS: TRUE when a device is found, FALSE otherwise.
 */
static gboolean
find_device_for_connection (NmCli *nmc,
                            NMConnection *connection,
                            const char *iface,
                            const char *ap,
                            const char *nsp,
                            NMDevice **device,
                            const char **spec_object,
                            GError **error)
{
	NMSettingConnection *s_con;
	const char *con_type;
	int i, j;

	g_return_val_if_fail (nmc != NULL, FALSE);
	g_return_val_if_fail (device != NULL && *device == NULL, FALSE);
	g_return_val_if_fail (spec_object != NULL && *spec_object == NULL, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	con_type = nm_setting_connection_get_connection_type (s_con);

	if (strcmp (con_type, NM_SETTING_VPN_SETTING_NAME) == 0) {
		/* VPN connections */
		NMActiveConnection *active = NULL;
		if (iface) {
			*device = nm_client_get_device_by_iface (nmc->client, iface);
			if (*device)
				active = nm_device_get_active_connection (*device);

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
				    && nm_device_connection_compatible (dev, connection, NULL)) {
					found_device = dev;
				}
			} else {
				if (nm_device_connection_compatible (dev, connection, NULL)) {
					found_device = dev;
				}
			}

			if (found_device && ap && !strcmp (con_type, NM_SETTING_WIRELESS_SETTING_NAME) && NM_IS_DEVICE_WIFI (dev)) {
				char *bssid_up = g_ascii_strup (ap, -1);
				const GPtrArray *aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (dev));
				found_device = NULL;  /* Mark as not found; set to the device again later, only if AP matches */

				for (j = 0; aps && (j < aps->len); j++) {
					NMAccessPoint *candidate_ap = g_ptr_array_index (aps, j);
					const char *candidate_bssid = nm_access_point_get_bssid (candidate_ap);

					if (!strcmp (bssid_up, candidate_bssid)) {
						found_device = dev;
						*spec_object = nm_object_get_path (NM_OBJECT (candidate_ap));
						break;
					}
				}
				g_free (bssid_up);
			}

#if WITH_WIMAX
			if (   found_device
			    && nsp
			    && !strcmp (con_type, NM_SETTING_WIMAX_SETTING_NAME)
			    && NM_IS_DEVICE_WIMAX (dev)) {
				const GPtrArray *nsps = nm_device_wimax_get_nsps (NM_DEVICE_WIMAX (dev));
				found_device = NULL;  /* Mark as not found; set to the device again later, only if NSP matches */

				for (j = 0; nsps && (j < nsps->len); j++) {
					NMWimaxNsp *candidate_nsp = g_ptr_array_index (nsps, j);
					const char *candidate_name = nm_wimax_nsp_get_name (candidate_nsp);

					if (!strcmp (nsp, candidate_name)) {
						found_device = dev;
						*spec_object = nm_object_get_path (NM_OBJECT (candidate_nsp));
						break;
					}
				}
			}
#endif
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
activate_connection_cb (NMClient *client, NMActiveConnection *active, GError *error, gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;
	NMActiveConnectionState state;

	if (error) {
		g_string_printf (nmc->return_text, _("Error: Connection activation failed: %s"), error->message);
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		quit ();
	} else {
		state = nm_active_connection_get_state (active);

		printf (_("Active connection state: %s\n"), active_connection_state_to_string (state));
		printf (_("Active connection path: %s\n"), nm_object_get_path (NM_OBJECT (active)));

		if (nmc->nowait_flag || state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
			/* don't want to wait or already activated */
			quit ();
		} else {
			if (NM_IS_VPN_CONNECTION (active))
				g_signal_connect (NM_VPN_CONNECTION (active), "vpn-state-changed", G_CALLBACK (vpn_connection_state_cb), nmc);
			else
				g_signal_connect (active, "notify::state", G_CALLBACK (active_connection_state_cb), nmc);

			/* Start timer not to loop forever when signals are not emitted */
			g_timeout_add_seconds (nmc->timeout, timeout_cb, nmc);
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
	const char *con_type;
	const char *iface = NULL;
	const char *ap = NULL;
	const char *nsp = NULL;
	gboolean id_specified = FALSE;
	gboolean wait = TRUE;
	GError *error = NULL;
	gboolean is_virtual = FALSE;

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

			connection = find_connection (nmc->system_connections, selector, *argv);

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
#if WITH_WIMAX
		else if (strcmp (*argv, "nsp") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}

			nsp = *argv;
		}
#endif
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

	if (!nmc_is_nm_running (nmc, &error)) {
		if (error) {
			g_string_printf (nmc->return_text, _("Error: Can't find out if NetworkManager is running: %s."), error->message);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			g_error_free (error);
		} else {
			g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
			nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		}
		goto error;
	}

	/* create NMClient */
	nmc->get_client (nmc);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	con_type = nm_setting_connection_get_connection_type (s_con);

	if (   nm_connection_is_type (connection, NM_SETTING_BOND_SETTING_NAME)
	    || nm_connection_is_type (connection, NM_SETTING_VLAN_SETTING_NAME))
		is_virtual = TRUE;

	device_found = find_device_for_connection (nmc, connection, iface, ap, nsp, &device, &spec_object, &error);
	/* Virtual connection may not have their interfaces created yet */
	if (!device_found && !is_virtual) {
		if (error)
			g_string_printf (nmc->return_text, _("Error: No suitable device found: %s."), error->message);
		else
			g_string_printf (nmc->return_text, _("Error: No suitable device found."));
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		g_clear_error (&error);
		goto error;
	}

	/* Use nowait_flag instead of should_wait because exiting has to be postponed till
	 * active_connection_state_cb() is called. That gives NM time to check our permissions
	 * and we can follow activation progress.
	 */
	nmc->nowait_flag = !wait;
	nmc->should_wait = TRUE;
	nm_client_activate_connection (nmc->client,
	                               connection,
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
	GError *error = NULL;
	const GPtrArray *active_cons;
	const char *con_path;
	const char *active_path;
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

			connection = find_connection (nmc->system_connections, selector, *argv);

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

	if (!nmc_is_nm_running (nmc, &error)) {
		if (error) {
			g_string_printf (nmc->return_text, _("Error: Can't find out if NetworkManager is running: %s."), error->message);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			g_error_free (error);
		} else {
			g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
			nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		}
		goto error;
	}

	/* create NMClient */
	nmc->get_client (nmc);

	con_path = nm_connection_get_path (connection);

	active_cons = nm_client_get_active_connections (nmc->client);
	for (i = 0; active_cons && (i < active_cons->len); i++) {
		NMActiveConnection *candidate = g_ptr_array_index (active_cons, i);

		active_path = nm_active_connection_get_connection (candidate);
		if (!strcmp (active_path, con_path)) {
			active = candidate;
			break;
		}
	}

	if (active)
		nm_client_deactivate_connection (nmc->client, active);
	else
		fprintf (stderr, _("Warning: Connection not active\n"));
	sleep (1);  /* Don't quit immediatelly and give NM time to check our permissions */

error:
	nmc->should_wait = FALSE;
	return nmc->return_value;
}

static void
delete_cb (NMRemoteConnection *con, GError *err, gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;

	if (err) {
		g_string_printf (nmc->return_text, _("Error: Connection deletion failed: %s"), err->message);
		nmc->return_value = NMC_RESULT_ERROR_CON_DEL;
	}
	quit ();
}

static void
connection_removed_cb (NMRemoteConnection *con, gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;

	nmc->return_value = NMC_RESULT_SUCCESS;
	quit ();
}

static NMCResultCode
do_connection_delete (NmCli *nmc, int argc, char **argv)
{
	NMConnection *connection = NULL;
	const char *selector = NULL;
	const char *id = NULL;
	GError *error = NULL;

	while (argc > 0) {
		if (strcmp (*argv, "id") == 0 || strcmp (*argv, "uuid") == 0) {
			selector = *argv;
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			id = *argv;
		}
		else
			fprintf (stderr, _("Unknown parameter: %s\n"), *argv);

		argc--;
		argv++;
	}

	if (!id) {
		g_string_printf (nmc->return_text, _("Error: id or uuid has to be specified."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}

	if (!nmc_is_nm_running (nmc, &error)) {
		if (error) {
			g_string_printf (nmc->return_text, _("Error: Can't find out if NetworkManager is running: %s."), error->message);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			g_error_free (error);
		} else {
			g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
			nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		}
		goto error;
	}

	connection = find_connection (nmc->system_connections, selector, id);

	if (!connection) {
		g_string_printf (nmc->return_text, _("Error: Unknown connection: %s."), id);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto error;
	}

	/* We need to wait a bit so that nmcli's permissions can be queried.
	 * We will exit either on "Removed" signal or when D-Bus return (error)
	 * message is received.
	 */
	nmc->should_wait = TRUE;

	/* Connect to "Removed" signal to be able to exit when connection was removed */
	g_signal_connect (connection, NM_REMOTE_CONNECTION_REMOVED, G_CALLBACK (connection_removed_cb), nmc);

	/* Delete the connection */
	nm_remote_connection_delete (NM_REMOTE_CONNECTION (connection), delete_cb, nmc);

	return nmc->return_value;

error:
	nmc->should_wait = FALSE;
	return nmc->return_value;
}

static NMCResultCode
parse_cmd (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;

	if (argc == 0) {
		if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
			goto opt_error;
		nmc->return_value = do_connections_list (nmc, argc, argv);
	} else {

		if (matches (*argv, "list") == 0) {
			nmc->return_value = do_connections_list (nmc, argc-1, argv+1);
		}
		else if (matches(*argv, "status") == 0) {
			if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
				goto opt_error;
			nmc->return_value = do_connections_status (nmc, argc-1, argv+1);
		}
		else if (matches(*argv, "up") == 0) {
			nmc->return_value = do_connection_up (nmc, argc-1, argv+1);
		}
		else if (matches(*argv, "down") == 0) {
			nmc->return_value = do_connection_down (nmc, argc-1, argv+1);
		}
		else if (matches(*argv, "delete") == 0) {
			nmc->return_value = do_connection_delete (nmc, argc-1, argv+1);
		}
		else if (matches (*argv, "help") == 0) {
			usage ();
			nmc->should_wait = FALSE;
		} else {
			usage ();
			g_string_printf (nmc->return_text, _("Error: 'con' command '%s' is not valid."), *argv);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			nmc->should_wait = FALSE;
		}
	}

	return nmc->return_value;

opt_error:
	g_string_printf (nmc->return_text, _("Error: %s."), error->message);
	nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
	nmc->should_wait = FALSE;
	g_error_free (error);
	return nmc->return_value;
}

/* callback called when connections are obtained from the settings service */
static void
get_connections_cb (NMRemoteSettings *settings, gpointer user_data)
{
	ArgsInfo *args = (ArgsInfo *) user_data;

	/* Get the connection list */
	args->nmc->system_connections = nm_remote_settings_list_connections (settings);

	parse_cmd (args->nmc, args->argc, args->argv);

	if (!args->nmc->should_wait)
		quit ();
}

/* Entry point function for connections-related commands: 'nmcli con' */
NMCResultCode
do_connections (NmCli *nmc, int argc, char **argv)
{
	DBusGConnection *bus;
	GError *error = NULL;
	int i = 0;
	gboolean real_cmd = FALSE;

	if (argc == 0)
		real_cmd = TRUE;
	else {
		while (real_con_commands[i] && matches (*argv, real_con_commands[i]) != 0)
			i++;
		if (real_con_commands[i] != NULL)
			real_cmd = TRUE;
	}

	if (!real_cmd) {
		/* no real execution command - no need to get connections */
		return parse_cmd (nmc, argc, argv);
	} else {
		if (!nmc_versions_match (nmc))
			return nmc->return_value;

		nmc->should_wait = TRUE;

		args_info.nmc = nmc;
		args_info.argc = argc;
		args_info.argv = argv;

		/* connect to DBus' system bus */
		bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
		if (error || !bus) {
			g_string_printf (nmc->return_text, _("Error: could not connect to D-Bus."));
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			nmc->should_wait = FALSE;
			return nmc->return_value;
		}

		/* get system settings */
		if (!(nmc->system_settings = nm_remote_settings_new (bus))) {
			g_string_printf (nmc->return_text, _("Error: Could not get system settings."));
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			nmc->should_wait = FALSE;
			return nmc->return_value;
		}

		/* find out whether settings service is running */
		g_object_get (nmc->system_settings, NM_REMOTE_SETTINGS_SERVICE_RUNNING, &nmc->system_settings_running, NULL);

		if (!nmc->system_settings_running) {
			g_string_printf (nmc->return_text, _("Error: Can't obtain connections: settings service is not running."));
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			nmc->should_wait = FALSE;
			return nmc->return_value;
		}

		/* connect to signal "connections-read" - emitted when connections are fetched and ready */
		g_signal_connect (nmc->system_settings, NM_REMOTE_SETTINGS_CONNECTIONS_READ,
				  G_CALLBACK (get_connections_cb), &args_info);


		dbus_g_connection_unref (bus);

		/* The rest will be done in get_connection_cb() callback.
		 * We need to wait for signals that connections are read.
		 */
		return NMC_RESULT_SUCCESS;
	}
}
