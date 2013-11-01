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
 * (C) Copyright 2010 - 2013 Red Hat, Inc.
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
#include <nm-device-adsl.h>
#include <nm-device-wifi.h>
#if WITH_WIMAX
#include <nm-device-wimax.h>
#endif
#include <nm-device-modem.h>
#include <nm-device-bt.h>
#include <nm-device-olpc-mesh.h>
#include <nm-device-infiniband.h>
#include <nm-device-bond.h>
#include <nm-device-team.h>
#include <nm-device-bridge.h>
#include <nm-device-vlan.h>
#include <nm-remote-settings.h>
#include <nm-vpn-connection.h>
#include <nm-utils.h>

#include "utils.h"
#include "common.h"
#include "settings.h"
#include "connections.h"

/* Activation timeout waiting for bond/team/bridge slaves (in seconds) */
#define SLAVES_UP_TIMEOUT 10

/* define some prompts for connection editor */
#define EDITOR_PROMPT_SETTING  _("Setting name? ")
#define EDITOR_PROMPT_PROPERTY _("Property name? ")
#define EDITOR_PROMPT_CON_TYPE _("Enter connection type: ")

/* Available fields for 'connection show configured' */
static NmcOutputField nmc_fields_con_show[] = {
	{"NAME",            N_("NAME"),           25},  /* 0 */
	{"UUID",            N_("UUID"),           38},  /* 1 */
	{"TYPE",            N_("TYPE"),           17},  /* 2 */
	{"TIMESTAMP",       N_("TIMESTAMP"),      12},  /* 3 */
	{"TIMESTAMP-REAL",  N_("TIMESTAMP-REAL"), 34},  /* 4 */
	{"AUTOCONNECT",     N_("AUTOCONNECT"),    13},  /* 5 */
	{"READONLY",        N_("READONLY"),       10},  /* 6 */
	{"DBUS-PATH",       N_("DBUS-PATH"),      42},  /* 7 */
	{NULL,              NULL,                  0}
};
#define NMC_FIELDS_CON_SHOW_ALL     "NAME,UUID,TYPE,TIMESTAMP,TIMESTAMP-REAL,AUTOCONNECT,READONLY,DBUS-PATH"
#define NMC_FIELDS_CON_SHOW_COMMON  "NAME,UUID,TYPE,TIMESTAMP-REAL"

/* Helper macro to define fields */
#define SETTING_FIELD(setting, width) { setting, N_(setting), width, NULL, FALSE, FALSE, 0 }

/* Available settings for 'connection show configured <con>' */
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
	SETTING_FIELD (NM_SETTING_ADSL_SETTING_NAME, 0),                  /* 19 */
	SETTING_FIELD (NM_SETTING_BRIDGE_SETTING_NAME, 0),                /* 20 */
	SETTING_FIELD (NM_SETTING_BRIDGE_PORT_SETTING_NAME, 0),           /* 21 */
	SETTING_FIELD (NM_SETTING_TEAM_SETTING_NAME, 0),                  /* 22 */
	SETTING_FIELD (NM_SETTING_TEAM_PORT_SETTING_NAME, 0),             /* 23 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
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
                                         NM_SETTING_ADSL_SETTING_NAME","\
                                         NM_SETTING_GSM_SETTING_NAME","\
                                         NM_SETTING_CDMA_SETTING_NAME","\
                                         NM_SETTING_BLUETOOTH_SETTING_NAME","\
                                         NM_SETTING_OLPC_MESH_SETTING_NAME","\
                                         NM_SETTING_VPN_SETTING_NAME","\
                                         NM_SETTING_INFINIBAND_SETTING_NAME","\
                                         NM_SETTING_BOND_SETTING_NAME","\
                                         NM_SETTING_VLAN_SETTING_NAME","\
                                         NM_SETTING_BRIDGE_SETTING_NAME","\
                                         NM_SETTING_BRIDGE_PORT_SETTING_NAME","\
                                         NM_SETTING_TEAM_SETTING_NAME","\
                                         NM_SETTING_TEAM_PORT_SETTING_NAME
#if WITH_WIMAX
#define NMC_FIELDS_SETTINGS_NAMES_ALL    NMC_FIELDS_SETTINGS_NAMES_ALL_X","\
                                         NM_SETTING_WIMAX_SETTING_NAME
#else
#define NMC_FIELDS_SETTINGS_NAMES_ALL    NMC_FIELDS_SETTINGS_NAMES_ALL_X
#endif


/* Available fields for 'connection show active' */
static NmcOutputField nmc_fields_con_show_active[] = {
	{"GROUP",         N_("GROUP"),         9},  /* 0 */  /* used only for 'GENERAL' group listing */
	{"NAME",          N_("NAME"),         25},  /* 1 */
	{"UUID",          N_("UUID"),         38},  /* 2 */
	{"DEVICES",       N_("DEVICES"),      10},  /* 3 */
	{"STATE",         N_("STATE"),        12},  /* 4 */
	{"DEFAULT",       N_("DEFAULT"),       8},  /* 5 */
	{"DEFAULT6",      N_("DEFAULT6"),      9},  /* 6 */
	{"SPEC-OBJECT",   N_("SPEC-OBJECT"),  10},  /* 7 */
	{"VPN",           N_("VPN"),           5},  /* 8 */
	{"DBUS-PATH",     N_("DBUS-PATH"),    51},  /* 9 */
	{"CON-PATH",      N_("CON-PATH"),     44},  /* 10 */
	{"ZONE",          N_("ZONE"),         15},  /* 11 */
	{"MASTER-PATH",   N_("MASTER-PATH"),  44},  /* 12 */
	{NULL,            NULL,                0}
};
#define NMC_FIELDS_CON_ACTIVE_ALL     "NAME,UUID,DEVICES,STATE,DEFAULT,DEFAULT6,VPN,ZONE,DBUS-PATH,CON-PATH,SPEC-OBJECT,MASTER-PATH"
#define NMC_FIELDS_CON_ACTIVE_COMMON  "NAME,UUID,DEVICES,DEFAULT,VPN,MASTER-PATH"

/* Available fields for 'connection show active <con>' */
static NmcOutputField nmc_fields_con_active_details_groups[] = {
	{"GENERAL",  N_("GENERAL"), 9},  /* 0 */
	{"IP",       N_("IP"),      5},  /* 1 */
	{"VPN",      N_("VPN"),     5},  /* 2 */
	{NULL, NULL, 0}
};
#define NMC_FIELDS_CON_ACTIVE_DETAILS_ALL  "GENERAL,IP,VPN"

/* GENERAL group is the same as nmc_fields_con_show_active */
#define NMC_FIELDS_CON_ACTIVE_DETAILS_GENERAL_ALL  "GROUP,"NMC_FIELDS_CON_ACTIVE_ALL

/* IP group is handled by common.c */

/* Available fields for VPN group */
static NmcOutputField nmc_fields_con_active_details_vpn[] = {
	{"GROUP",     N_("GROUP"),       9},  /* 0 */
	{"TYPE",      N_("TYPE"),       15},  /* 1 */
	{"USERNAME",  N_("USERNAME"),   15},  /* 2 */
	{"GATEWAY",   N_("GATEWAY"),    25},  /* 3 */
	{"BANNER",    N_("BANNER"),    120},  /* 4 */
	{"VPN-STATE", N_("VPN-STATE"),  40},  /* 5 */
	{"CFG",       N_("CFG"),       120},  /* 6 */
	{NULL, NULL, 0}
};
#define NMC_FIELDS_CON_ACTIVE_DETAILS_VPN_ALL  "GROUP,TYPE,USERNAME,GATEWAY,BANNER,VPN-STATE,CFG"


typedef struct {
	NmCli *nmc;
	int argc;
	char **argv;
} ArgsInfo;

/* glib main loop variable - defined in nmcli.c */
extern GMainLoop *loop;

static ArgsInfo args_info;
static guint progress_id = 0;  /* ID of event source for displaying progress */

/* for readline TAB completion */
typedef struct {
	NmCli *nmc;
	const char *con_type;
	NMConnection *connection;
	NMSetting *setting;
} TabCompletionInfo;
static TabCompletionInfo nmc_tab_completion = {NULL, NULL, NULL, NULL};

static void
usage (void)
{
	fprintf (stderr,
	         _("Usage: nmcli connection { COMMAND | help }\n"
	         "  COMMAND := { show | up | down | delete }\n\n"
	         "  show configured [[ id | uuid | path ] <ID>]\n\n"
	         "  show active     [[ id | uuid | path | apath ] <ID>]\n\n"
#if WITH_WIMAX
	         "  up [[ id | uuid | path ] <ID>] [ifname <ifname>] [ap <BSSID>] [nsp <name>]\n\n"
#else
	         "  up [[ id | uuid | path ] <ID>] [ifname <ifname>] [ap <BSSID>]\n\n"
#endif
	         "  down [ id | uuid | path | apath ] <ID>\n\n"
	         "  add COMMON_OPTIONS TYPE_SPECIFIC_OPTIONS IP_OPTIONS\n\n"
	         "  modify [ id | uuid | path ] <ID> <setting>.<property> <value>\n\n"
	         "  edit [ id | uuid | path ] <ID>  |  [type <new_con_type>] [con-name <new_con_name>]\n\n"
	         "  delete [ id | uuid | path ] <ID>\n\n"
	         "  reload\n\n\n"
	         ));
}

static void
usage_connection_add (void)
{
	fprintf (stderr,
	         _("Usage: nmcli connection add { OPTIONS | help }\n"
	         "  OPTIONS := COMMON_OPTIONS TYPE_SPECIFIC_OPTIONS IP_OPTIONS\n\n"
	         "  COMMON_OPTIONS:\n"
	         "                  type <type>\n"
	         "                  ifname <interface name> | \"*\"\n"
	         "                  [con-name <connection name>]\n"
	         "                  [autoconnect yes|no]\n\n"
	         "  TYPE_SPECIFIC_OPTIONS:\n"
	         "    ethernet:     [mac <MAC address>]\n"
	         "                  [cloned-mac <cloned MAC address>]\n"
	         "                  [mtu <MTU>]\n\n"
	         "    wifi:         ssid <SSID>\n"
	         "                  [mac <MAC address>]\n"
	         "                  [cloned-mac <cloned MAC address>]\n"
	         "                  [mtu <MTU>]\n\n"
	         "    wimax:        [mac <MAC address>]\n"
	         "                  [nsp <NSP>]\n\n"
	         "    gsm:          apn <APN>\n"
	         "                  [user <username>]\n"
	         "                  [password <password>]\n\n"
	         "    cdma:         [user <username>]\n"
	         "                  [password <password>]\n\n"
	         "    infiniband:   [mac <MAC address>]\n"
	         "                  [mtu <MTU>]\n"
	         "                  [transport-mode datagram | connected]\n"
	         "                  [parent <ifname>]\n"
	         "                  [p-key <IPoIB P_Key>]\n\n"
	         "    bluetooth:    [addr <bluetooth address>]\n"
	         "                  [bt-type panu|dun-gsm|dun-cdma]\n\n"
	         "    vlan:         dev <parent device (connection  UUID, ifname, or MAC)>\n"
	         "                  [id <VLAN id>]\n"
	         "                  [flags <VLAN flags>]\n"
	         "                  [ingress <ingress priority mapping>]\n"
	         "                  [egress <egress priority mapping>]\n"
	         "                  [mtu <MTU>]\n\n"
	         "    bond:         [mode balance-rr (0) | active-backup (1) | balance-xor (2) | broadcast (3) |\n"
	         "                        802.3ad    (4) | balance-tlb   (5) | balance-alb (6)]\n"
	         "                  [primary <ifname>]\n"
	         "                  [miimon <num>]\n"
	         "                  [downdelay <num>]\n"
	         "                  [updelay <num>]\n"
	         "                  [arp-interval <num>]\n"
	         "                  [arp-ip-target <num>]\n\n"
	         "    bond-slave:   master <master (ifname or connection UUID)>\n\n"
	         "    team:         [config <json config>]\n\n"
	         "    team-slave:   master <master (ifname or connection UUID)>\n"
	         "                  [config <json config>]\n\n"
	         "    bridge:       [stp yes|no>]\n"
	         "                  [priority <num>]\n"
	         "                  [forward-delay <2-30>]\n"
	         "                  [hello-time <1-10>]\n"
	         "                  [max-age <6-40>]\n"
	         "                  [ageing-time <0-1000000>]\n\n"
	         "    bridge-slave: master <master (ifname or connection UUID)\n"
	         "                  [priority <0-63>]\n"
	         "                  [path-cost <1-65535>]\n"
	         "                  [hairpin yes|no]\n\n"
	         "    vpn:          vpn-type vpnc|openvpn|pptp|openconnect|openswan\n"
	         "                  [user <username>]\n\n"
	         "    olpc-mesh:    ssid <SSID>\n"
	         "                  [channel <1-13>]\n"
	         "                  [dhcp-anycast <MAC address>]\n\n"
	         "  IP_OPTIONS:\n"
	         "                  [ip4 <IPv4 address>] [gw4 <IPv4 gateway>]\n"
	         "                  [ip6 <IPv6 address>] [gw6 <IPv6 gateway>]\n"
	         ));
}

/* The real commands that do something - i.e. not 'help', etc. */
static const char *real_con_commands[] = {
	"show",
	"up",
	"down",
	"add",
	"modify",
	"edit",
	"delete",
	"reload",
	NULL
};

/* quit main loop */
static void
quit (void)
{
	if (progress_id) {
		g_source_remove (progress_id);
		progress_id = 0;
		nmc_terminal_erase_line ();
	}

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
			g_string_printf (nmc->return_text, _("Error: 'list configured': %s"), error->message);
		else
			g_string_printf (nmc->return_text, _("Error: 'list configured': %s; allowed fields: %s"),
			                 error->message, NMC_FIELDS_SETTINGS_NAMES_ALL);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return FALSE;
	}

	/* Main header */
	nmc->print_fields.header_name = _("Connection details");
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTINGS_NAMES_ALL,
	                                                 nmc_fields_settings_names, NULL);

	nmc_fields_settings_names[0].flags = NMC_OF_FLAG_MAIN_HEADER_ONLY;
	print_required_fields (nmc, nmc_fields_settings_names);

	/* Loop through the required settings and print them. */
	for (i = 0; i < print_settings_array->len; i++) {
		NMSetting *setting;
		int section_idx = g_array_index (print_settings_array, int, i);

		if (nmc->print_output != NMC_PRINT_TERSE && !nmc->multiline_output && was_output)
			printf ("\n"); /* Empty line */

		was_output = FALSE;

		/* Remove any previous data */
		nmc_empty_output_fields (nmc);

		setting = nm_connection_get_setting_by_name (connection, nmc_fields_settings_names[section_idx].name);
		if (setting) {
			setting_details (setting, nmc);
			was_output = TRUE;
			continue;
		}
	}

	if (print_settings_array)
		g_array_free (print_settings_array, TRUE);

	return TRUE;
}

static void
fill_output_connection (gpointer data, gpointer user_data)
{
	NMConnection *connection = (NMConnection *) data;
	NmCli *nmc = (NmCli *) user_data;
	NMSettingConnection *s_con;
	guint64 timestamp;
	time_t timestamp_real;
	char *timestamp_str;
	char *timestamp_real_str;
	NmcOutputField *arr;

	s_con = nm_connection_get_setting_connection (connection);
	if (s_con) {
		/* Obtain field values */
		timestamp = nm_setting_connection_get_timestamp (s_con);
		timestamp_str = g_strdup_printf ("%" G_GUINT64_FORMAT, timestamp);
		if (timestamp) {
			timestamp_real = timestamp;
			timestamp_real_str = g_malloc0 (64);
			strftime (timestamp_real_str, 64, "%c", localtime (&timestamp_real));
		}

		arr = nmc_dup_fields_array (nmc_fields_con_show,
		                            sizeof (nmc_fields_con_show),
		                            0);
		set_val_strc (arr, 0, nm_setting_connection_get_id (s_con));
		set_val_strc (arr, 1, nm_setting_connection_get_uuid (s_con));
		set_val_strc (arr, 2, nm_setting_connection_get_connection_type (s_con));
		set_val_str  (arr, 3, timestamp_str);
		set_val_str  (arr, 4, timestamp ? timestamp_real_str : g_strdup (_("never")));
		set_val_strc (arr, 5, nm_setting_connection_get_autoconnect (s_con) ? _("yes") : _("no"));
		set_val_strc (arr, 6, nm_setting_connection_get_read_only (s_con) ? _("yes") : _("no"));
		set_val_strc (arr, 7, nm_connection_get_path (connection));

		g_ptr_array_add (nmc->output_data, arr);
	}
}

static NMConnection *
find_connection (GSList *list, const char *filter_type, const char *filter_val)
{
	NMConnection *connection;
	GSList *iterator;
	const char *id;
	const char *uuid;
	const char *path, *path_num;

	iterator = list;
	while (iterator) {
		connection = NM_CONNECTION (iterator->data);

		id = nm_connection_get_id (connection);
		uuid = nm_connection_get_uuid (connection);
		path = nm_connection_get_path (connection);
		path_num = path ? strrchr (path, '/') + 1 : NULL;

		/* When filter_type is NULL, compare connection ID (filter_val)
		 * against all types. Otherwise, only compare against the specific
		 * type. If 'path' filter type is specified, comparison against
		 * numeric index (in addition to the whole path) is allowed.
		 */
		if (   (   (!filter_type || strcmp (filter_type, "id")  == 0)
		        && strcmp (filter_val, id) == 0)
		    || (   (!filter_type || strcmp (filter_type, "uuid") == 0)
		        && strcmp (filter_val, uuid) == 0)
		    || (   (!filter_type || strcmp (filter_type, "path") == 0)
		        && (g_strcmp0 (filter_val, path) == 0 || (filter_type && g_strcmp0 (filter_val, path_num) == 0))))
			return connection;

		iterator = g_slist_next (iterator);
	}

	return NULL;
}

static NMCResultCode
do_connections_show (NmCli *nmc, int argc, char **argv)
{
	GError *error1 = NULL;
	GError *error2 = NULL;
	char *fields_str;
	char *fields_all =    NMC_FIELDS_CON_SHOW_ALL;
	char *fields_common = NMC_FIELDS_CON_SHOW_COMMON;
	gboolean printed = FALSE;

	nmc->should_wait = FALSE;

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else
		fields_str = nmc->required_fields;

	if (argc == 0) {
		NmcOutputField *tmpl, *arr;
		size_t tmpl_len;

		tmpl = nmc_fields_con_show;
		tmpl_len = sizeof (nmc_fields_con_show);
		nmc->print_fields.indices = parse_output_fields (fields_str, tmpl, &error1);
		if (error1)
			goto error;
		if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error2))
			goto error;

		/* Add headers */
		nmc->print_fields.header_name = _("List of configured connections");
		arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
		g_ptr_array_add (nmc->output_data, arr);

		/* Add values */
		g_slist_foreach (nmc->system_connections, fill_output_connection, nmc);
		print_data (nmc);  /* Print all data */
	} else {
		while (argc > 0) {
			NMConnection *con;
			const char *selector = NULL;

			if (   strcmp (*argv, "id") == 0
			    || strcmp (*argv, "uuid") == 0
			    || strcmp (*argv, "path") == 0) {
				selector = *argv;
				if (next_arg (&argc, &argv) != 0) {
					g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					return nmc->return_value;
				}
			}
			if (!nmc->mode_specified)
				nmc->multiline_output = TRUE;  /* multiline mode is default for 'show configured <con>' */

			con = find_connection (nmc->system_connections, selector, *argv);
			if (con) {
				if (printed)
					printf ("\n");
				printed = nmc_connection_detail (con, nmc);
			} else {
				g_string_printf (nmc->return_text, _("Error: %s - no such connection."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
				return nmc->return_value;
			}

			argc--;
			argv++;
		}
	}

error:
	if (error1) {
		if (error1->code == 0)
			g_string_printf (nmc->return_text, _("Error: 'show configured': %s"), error1->message);
		else
			g_string_printf (nmc->return_text, _("Error: 'show configured': %s; allowed fields: %s"),
			                 error1->message, NMC_FIELDS_CON_SHOW_ALL);
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
	case NM_ACTIVE_CONNECTION_STATE_DEACTIVATED:
		return _("deactivated");
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

static void
fill_output_active_connection (NMActiveConnection *active,
                               NmCli *nmc,
                               gboolean with_group,
                               guint32 o_flags)
{
	GSList *iter;
	const char *active_path;
	NMSettingConnection *s_con;
	const GPtrArray *devices;
	GString *dev_str;
	NMActiveConnectionState state;
	int i;
	GSList *con_list = nmc->system_connections;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;
	int idx_start = with_group ? 0 : 1;

	active_path = nm_active_connection_get_connection (active);
	state = nm_active_connection_get_state (active);

	/* Get devices of the active connection */
	dev_str = g_string_new (NULL);
	devices = nm_active_connection_get_devices (active);
	for (i = 0; devices && (i < devices->len); i++) {
		NMDevice *device = g_ptr_array_index (devices, i);
		const char *dev_iface = nm_device_get_iface (device);

		if (dev_iface) {
			g_string_append (dev_str, dev_iface);
			g_string_append_c (dev_str, ',');
		}
	}
	if (dev_str->len > 0)
		g_string_truncate (dev_str, dev_str->len - 1);  /* Cut off last ',' */

	tmpl = nmc_fields_con_show_active;
	tmpl_len = sizeof (nmc_fields_con_show_active);
	if (!with_group) {
		tmpl++;
		tmpl_len -= sizeof (NmcOutputField);
	}

	/* Fill field values */
	arr = nmc_dup_fields_array (tmpl, tmpl_len, o_flags);
	if (with_group)
		set_val_strc (arr, 0, nmc_fields_con_active_details_groups[0].name);
	set_val_strc (arr, 1-idx_start, _("N/A"));
	set_val_strc (arr, 2-idx_start, nm_active_connection_get_uuid (active));
	set_val_str  (arr, 3-idx_start, dev_str->str);
	set_val_strc (arr, 4-idx_start, active_connection_state_to_string (state));
	set_val_strc (arr, 5-idx_start, nm_active_connection_get_default (active) ? _("yes") : _("no"));
	set_val_strc (arr, 6-idx_start, nm_active_connection_get_default6 (active) ? _("yes") : _("no"));
	set_val_strc (arr, 7-idx_start, nm_active_connection_get_specific_object (active));
	set_val_strc (arr, 8-idx_start, NM_IS_VPN_CONNECTION (active) ? _("yes") : _("no"));
	set_val_strc (arr, 9-idx_start, nm_object_get_path (NM_OBJECT (active)));
	set_val_strc (arr, 10-idx_start, nm_active_connection_get_connection (active));
	set_val_strc (arr, 11-idx_start, _("N/A"));
	set_val_strc (arr, 12-idx_start, nm_active_connection_get_master (active));

	for (iter = con_list; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = (NMConnection *) iter->data;
		const char *con_path = nm_connection_get_path (connection);

		if (!strcmp (active_path, con_path)) {
			/* This connection is active */
			s_con = nm_connection_get_setting_connection (connection);
			g_assert (s_con != NULL);

			/* Fill field values that depend on NMConnection */
			set_val_strc (arr, 1-idx_start,  nm_setting_connection_get_id (s_con));
			set_val_strc (arr, 11-idx_start, nm_setting_connection_get_zone (s_con));

			break;
		}
	}
	g_ptr_array_add (nmc->output_data, arr);

	g_string_free (dev_str, FALSE);
}

static NMActiveConnection *
find_active_connection (const GPtrArray *active_cons, const GSList *cons,
                        const char *filter_type, const char *filter_val)
{
	int i;
	const char *path, *a_path, *path_num, *a_path_num;
	const char *id;
	const char *uuid;
	NMConnection *con;

	for (i = 0; active_cons && (i < active_cons->len); i++) {
		NMActiveConnection *candidate = g_ptr_array_index (active_cons, i);

		path = nm_active_connection_get_connection (candidate);
		a_path = nm_object_get_path (NM_OBJECT (candidate));
		uuid = nm_active_connection_get_uuid (candidate);
		path_num = path ? strrchr (path, '/') + 1 : NULL;
		a_path_num = a_path ? strrchr (a_path, '/') + 1 : NULL;

		con = get_connection_for_active (cons, candidate);
		id = nm_connection_get_id (con);

		/* When filter_type is NULL, compare connection ID (filter_val)
		 * against all types. Otherwise, only compare against the specific
		 * type. If 'path' or 'apath' filter types are specified, comparison
		 * against numeric index (in addition to the whole path) is allowed.
		 */
		if (   (   (!filter_type || strcmp (filter_type, "id")  == 0)
		        && strcmp (filter_val, id) == 0)
		    || (   (!filter_type || strcmp (filter_type, "uuid") == 0)
		        && strcmp (filter_val, uuid) == 0)
		    || (   (!filter_type || strcmp (filter_type, "path") == 0)
		        && (g_strcmp0 (filter_val, path) == 0 || (filter_type && g_strcmp0 (filter_val, path_num) == 0)))
		    || (   (!filter_type || strcmp (filter_type, "apath") == 0)
		        && (g_strcmp0 (filter_val, a_path) == 0 || (filter_type && g_strcmp0 (filter_val, a_path_num) == 0))))
			return candidate;
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
	char *fields_all =    NMC_FIELDS_CON_ACTIVE_DETAILS_ALL;
	char *fields_common = NMC_FIELDS_CON_ACTIVE_DETAILS_ALL;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;
	gboolean was_output = FALSE;

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else
		fields_str = nmc->required_fields;

	print_groups = parse_output_fields (fields_str, nmc_fields_con_active_details_groups, &error);
	if (error) {
		if (error->code == 0)
			g_string_printf (nmc->return_text, _("Error: 'list active': %s"), error->message);
		else
			g_string_printf (nmc->return_text, _("Error: 'list active': %s; allowed fields: %s"),
			                 error->message, NMC_FIELDS_CON_ACTIVE_DETAILS_ALL);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return FALSE;
	}

	/* Main header */
	nmc->print_fields.header_name = _("Active connection details");
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_CON_ACTIVE_DETAILS_ALL,
	                                                 nmc_fields_con_active_details_groups, NULL);

	nmc_fields_con_active_details_groups[0].flags = NMC_OF_FLAG_MAIN_HEADER_ONLY;
	print_required_fields (nmc, nmc_fields_con_active_details_groups);

	/* Loop through the groups and print them. */
	for (i = 0; i < print_groups->len; i++) {
		int group_idx = g_array_index (print_groups, int, i);

		if (nmc->print_output != NMC_PRINT_TERSE && !nmc->multiline_output && was_output)
			printf ("\n"); /* Empty line */

		was_output = FALSE;

		/* Remove any previous data */
		nmc_empty_output_fields (nmc);

		/* GENERAL */
		if (strcasecmp (nmc_fields_con_active_details_groups[group_idx].name, nmc_fields_con_active_details_groups[0].name) == 0) {
			/* Add field names */
			tmpl = nmc_fields_con_show_active;
			tmpl_len = sizeof (nmc_fields_con_show_active);
			nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_CON_ACTIVE_DETAILS_GENERAL_ALL, tmpl, NULL);
			arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
			g_ptr_array_add (nmc->output_data, arr);

			/* Fill in values */
			fill_output_active_connection (acon, nmc, TRUE, NMC_OF_FLAG_SECTION_PREFIX);

			print_data (nmc);  /* Print all data */

			was_output = TRUE;
		}

		/* IP */
		if (strcasecmp (nmc_fields_con_active_details_groups[group_idx].name,  nmc_fields_con_active_details_groups[1].name) == 0) {
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
		    strcasecmp (nmc_fields_con_active_details_groups[group_idx].name,  nmc_fields_con_active_details_groups[2].name) == 0) {
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

			tmpl = nmc_fields_con_active_details_vpn;
			tmpl_len = sizeof (nmc_fields_con_active_details_vpn);
			nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_CON_ACTIVE_DETAILS_VPN_ALL, tmpl, NULL);
			arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
			g_ptr_array_add (nmc->output_data, arr);

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

			/* Add values */
			arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
			set_val_strc (arr, 0, nmc_fields_con_active_details_groups[2].name);
			set_val_str  (arr, 1, type_str);
			set_val_strc (arr, 2, username ? username : get_vpn_data_item (con, VPN_DATA_ITEM_USERNAME));
			set_val_strc (arr, 3, get_vpn_data_item (con, VPN_DATA_ITEM_GATEWAY));
			set_val_str  (arr, 4, banner_str);
			set_val_str  (arr, 5, vpn_state_str);
			set_val_arr  (arr, 6, vpn_data_array);
			g_ptr_array_add (nmc->output_data, arr);

			print_data (nmc);  /* Print all data */
			was_output = TRUE;
		}
	}

	if (print_groups)
		g_array_free (print_groups, TRUE);

	return TRUE;
}

static NMCResultCode
do_connections_show_active (NmCli *nmc, int argc, char **argv)
{
	const GPtrArray *active_cons;
	int i;
	GError *err1 = NULL;
	gboolean printed = FALSE;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	nmc->should_wait = FALSE;

	/* Get active connections */
	nmc->get_client (nmc);

	if (!nm_client_get_manager_running (nmc->client)) {
		g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
		nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		goto error;
	}

	active_cons = nm_client_get_active_connections (nmc->client);

	if (argc == 0) {
		char *fields_str;
		char *fields_all =    NMC_FIELDS_CON_ACTIVE_ALL;
		char *fields_common = NMC_FIELDS_CON_ACTIVE_COMMON;

		if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
			fields_str = fields_common;
		else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
			fields_str = fields_all;
		else
			fields_str = nmc->required_fields;

		tmpl = nmc_fields_con_show_active + 1;
		tmpl_len = sizeof (nmc_fields_con_show_active) - sizeof (NmcOutputField);
		nmc->print_fields.indices = parse_output_fields (fields_str, tmpl, &err1);
		if (err1)
			goto error;

		/* Add headers */
		nmc->print_fields.header_name = _("List of active connections");
		arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
		g_ptr_array_add (nmc->output_data, arr);

		/* Add values */
		for (i = 0; active_cons && i < active_cons->len; i++) {
			NMActiveConnection *ac = g_ptr_array_index (active_cons, i);
			fill_output_active_connection (ac, nmc, FALSE, 0);
		}
		print_data (nmc);  /* Print all data */
	} else {
		while (argc > 0) {
			NMActiveConnection *acon;
			const char *selector = NULL;

			if (   strcmp (*argv, "id") == 0
			    || strcmp (*argv, "uuid") == 0
			    || strcmp (*argv, "path") == 0
			    || strcmp (*argv, "apath") == 0) {

				selector = *argv;
				if (next_arg (&argc, &argv) != 0) {
					g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					return nmc->return_value;
				}
			}
			if (!nmc->mode_specified)
				nmc->multiline_output = TRUE;  /* multiline mode is default for 'show active <con>' */

			acon = find_active_connection (active_cons, nmc->system_connections, selector, *argv);
			if (acon) {
				if (printed)
					printf ("\n");
				printed = nmc_active_connection_detail (acon, nmc); /* separate connections by blank line */
			} else {
				g_string_printf (nmc->return_text, _("Error: '%s' is not an active connection."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
				return nmc->return_value;
			}

			argc--;
			argv++;
		}
	}

error:
	if (err1) {
		if (err1->code == 0)
			g_string_printf (nmc->return_text, _("Error: 'show active': %s"), err1->message);
		else
			g_string_printf (nmc->return_text, _("Error: 'show active': %s; allowed fields: %s"), err1->message, NMC_FIELDS_CON_ACTIVE_ALL);
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
				g_set_error (error, NMCLI_ERROR, 0, _("no active connection on device '%s'"), iface);
				return FALSE;
			}
			*spec_object = nm_object_get_path (NM_OBJECT (active));
			return TRUE;
		} else {
			active = get_default_active_connection (nmc, device);
			if (!active) {
				g_set_error_literal (error, NMCLI_ERROR, 0, _("no active connection or device"));
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
				if (   !g_strcmp0 (dev_iface, iface)
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
				g_set_error (error, NMCLI_ERROR, 0, _("device '%s' not compatible with connection '%s'"),
				             iface, nm_setting_connection_get_id (s_con));
			else
				g_set_error (error, NMCLI_ERROR, 0, _("no device found for connection '%s'"),
				             nm_setting_connection_get_id (s_con));
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

	if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
		if (nmc->print_output == NMC_PRINT_PRETTY)
			nmc_terminal_erase_line ();
		printf (_("Connection successfully activated (D-Bus active path: %s)\n"),
		        nm_object_get_path (NM_OBJECT (active)));
		quit ();
	} else if (   state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED
	           || state == NM_ACTIVE_CONNECTION_STATE_UNKNOWN) {
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
		/* no operation */
		break;

	case NM_VPN_CONNECTION_STATE_ACTIVATED:
		if (nmc->print_output == NMC_PRINT_PRETTY)
			nmc_terminal_erase_line ();
		printf (_("VPN connection successfully activated (D-Bus active path: %s)\n"),
		        nm_object_get_path (NM_OBJECT (vpn)));
		quit ();
		break;

	case NM_VPN_CONNECTION_STATE_FAILED:
	case NM_VPN_CONNECTION_STATE_DISCONNECTED:
		g_string_printf (nmc->return_text, _("Error: Connection activation failed: %s."),
		                 vpn_connection_state_reason_to_string (reason));
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

static gboolean
progress_cb (gpointer user_data)
{
	const char *str = (const char *) user_data;

	nmc_terminal_show_progress (str);

	return TRUE;
}

static gboolean
progress_device_cb (gpointer user_data)
{
	NMDevice *device = (NMDevice *) user_data;

	nmc_terminal_show_progress (device ? nmc_device_state_to_string (nm_device_get_state (device)) : "");

	return TRUE;
}

static gboolean
progress_vpn_cb (gpointer user_data)
{
	NMVPNConnection *vpn = (NMVPNConnection *) user_data;
	const char *str;

	str = NM_IS_VPN_CONNECTION (vpn) ?
	        vpn_connection_state_to_string (nm_vpn_connection_get_vpn_state (vpn)) :
	        "";

	nmc_terminal_show_progress (str);

	return TRUE;
}

typedef struct {
	NmCli *nmc;
	NMDevice *device;
} ActivateConnectionInfo;

static gboolean
master_iface_slaves_check (gpointer user_data)
{
	ActivateConnectionInfo *info = (ActivateConnectionInfo *) user_data;
	NmCli *nmc = info->nmc;
	NMDevice *device = info->device;
	const GPtrArray *slaves = NULL;

	if (NM_IS_DEVICE_BOND (device))
		slaves = nm_device_bond_get_slaves (NM_DEVICE_BOND (device));
	else if (NM_IS_DEVICE_TEAM (device))
		slaves = nm_device_team_get_slaves (NM_DEVICE_TEAM (device));
	else if (NM_IS_DEVICE_BRIDGE (device))
		slaves = nm_device_bridge_get_slaves (NM_DEVICE_BRIDGE (device));
	else
		g_warning ("%s: should not be reached.", __func__);

	if (!slaves) {
		g_string_printf (nmc->return_text,
		                 _("Error: Device '%s' is waiting for slaves before proceeding with activation."),
		                 nm_device_get_iface (device));
		nmc->return_value = NMC_RESULT_ERROR_TIMEOUT_EXPIRED;
		quit ();
	}

	g_free (info);
	return FALSE;
}

static void
activate_connection_cb (NMClient *client, NMActiveConnection *active, GError *error, gpointer user_data)
{
	ActivateConnectionInfo *info = (ActivateConnectionInfo *) user_data;
	NmCli *nmc = info->nmc;
	NMDevice *device = info->device;
	NMActiveConnectionState state;
	const GPtrArray *ac_devs;

	if (error) {
		g_string_printf (nmc->return_text, _("Error: Connection activation failed: %s"), error->message);
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		quit ();
	} else {
		state = nm_active_connection_get_state (active);
		if (!device) {
			/* device could be NULL for virtual devices. Fill it here. */
			ac_devs = nm_active_connection_get_devices (active);
			info->device = device = ac_devs && ac_devs->len > 0 ? g_ptr_array_index (ac_devs, 0) : NULL;
		}

		if (nmc->nowait_flag || state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
			/* User doesn't want to wait or already activated */
			if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
				if (nmc->print_output == NMC_PRINT_PRETTY)
					nmc_terminal_erase_line ();
				printf (_("Connection successfully activated (D-Bus active path: %s)\n"),
				        nm_object_get_path (NM_OBJECT (active)));
			}
			quit ();
		} else {
			if (NM_IS_VPN_CONNECTION (active)) {
				/* Monitor VPN state */
				g_signal_connect (G_OBJECT (active), "vpn-state-changed", G_CALLBACK (vpn_connection_state_cb), nmc);

				/* Start progress indication showing VPN states */
				if (nmc->print_output == NMC_PRINT_PRETTY) {
					if (progress_id)
						g_source_remove (progress_id);
					progress_id = g_timeout_add (120, progress_vpn_cb, NM_VPN_CONNECTION (active));
				}
			} else {
				g_signal_connect (active, "notify::state", G_CALLBACK (active_connection_state_cb), nmc);

				/* Start progress indication showing device states */
				if (nmc->print_output == NMC_PRINT_PRETTY) {
					if (progress_id)
						g_source_remove (progress_id);
					progress_id = g_timeout_add (120, progress_device_cb, device);
				}
			}

			/* Start timer not to loop forever when signals are not emitted */
			g_timeout_add_seconds (nmc->timeout, timeout_cb, nmc);

			/* Check for bond or team or bridge slaves */
			if (   NM_IS_DEVICE_BOND (device)
			    || NM_IS_DEVICE_TEAM (device)
			    || NM_IS_DEVICE_BRIDGE (device)) {
				g_timeout_add_seconds (SLAVES_UP_TIMEOUT, master_iface_slaves_check, info);
				return; /* info will be freed in master_iface_slaves_check () */
			}
		}
	}
	g_free (info);
}

static gboolean
nmc_activate_connection (NmCli *nmc,
                         NMConnection *connection,
                         const char *ifname,
                         const char *ap,
                         const char *nsp,
                         NMClientActivateFn callback,
                         GError **error)
{
	ActivateConnectionInfo *info;
	NMDevice *device = NULL;
	const char *spec_object = NULL;
	gboolean device_found;
	gboolean is_virtual = FALSE;
	GError *local = NULL;

	g_return_val_if_fail (nmc != NULL, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (connection) {
		if (nm_connection_get_virtual_iface_name (connection))
			is_virtual = TRUE;

		device_found = find_device_for_connection (nmc, connection, ifname, ap, nsp, &device, &spec_object, &local);
		/* Virtual connection may not have their interfaces created yet */
		if (!device_found && !is_virtual) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_CON_ACTIVATION,
				     "%s", local && local->message ? local->message : _("unknown error"));
			g_clear_error (&local);
			return FALSE;
		}
	} else if (ifname) {
		device = nm_client_get_device_by_iface (nmc->client, ifname);
		if (!device) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_CON_ACTIVATION,
			             _("unknown device '%s'."), ifname);
			return FALSE;
		}
	} else {
		g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_CON_ACTIVATION,
		                     _("neither a valid connection nor device given"));
		return FALSE;
	}

	info = g_malloc0 (sizeof (ActivateConnectionInfo));
	info->nmc = nmc;
	info->device = device;

	nm_client_activate_connection (nmc->client,
	                               connection,
	                               device,
	                               spec_object,
	                               callback,
	                               info);
	return TRUE;
}

static NMCResultCode
do_connection_up (NmCli *nmc, int argc, char **argv)
{
	NMConnection *connection = NULL;
	const char *ifname = NULL;
	const char *ap = NULL;
	const char *nsp = NULL;
	GError *error = NULL;
	const char *selector = NULL;
	const char *name = NULL;
	char *line = NULL;

	/*
	 * Set default timeout for connection activation.
	 * Activation can take quite a long time, use 90 seconds.
	 */
	if (nmc->timeout == -1)
		nmc->timeout = 90;

	if (argc == 0) {
		if (nmc->ask) {
			line = nmc_get_user_input (_("Connection (name, UUID, or path): "));
			name = line ? line : "";
			// TODO: enhancement:  when just Enter is pressed (line is NULL), list
			// available connections so that the user can select one
		}
	} else if (strcmp (*argv, "ifname") != 0) {
		if (   strcmp (*argv, "id") == 0
		    || strcmp (*argv, "uuid") == 0
		    || strcmp (*argv, "path") == 0) {

			selector = *argv;
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), selector);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			name = *argv;
		}
		name = *argv;
		next_arg (&argc, &argv);
	}

	if (name)
		connection = find_connection (nmc->system_connections, selector, name);

	while (argc > 0) {
		if (strcmp (*argv, "ifname") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}

			ifname = *argv;
		}
		else if (strcmp (*argv, "ap") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}

			ap = *argv;
		}
#if WITH_WIMAX
		else if (strcmp (*argv, "nsp") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}

			nsp = *argv;
		}
#endif
		 else {
			fprintf (stderr, _("Unknown parameter: %s\n"), *argv);
		}

		argc--;
		argv++;
	}

	/* create NMClient */
	nmc->get_client (nmc);

	if (!nm_client_get_manager_running (nmc->client)) {
		g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
		nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		goto error;
	}

	/* Use nowait_flag instead of should_wait because exiting has to be postponed till
	 * active_connection_state_cb() is called. That gives NM time to check our permissions
	 * and we can follow activation progress.
	 */
	nmc->nowait_flag = (nmc->timeout == 0);
	nmc->should_wait = TRUE;

	if (!nmc_activate_connection (nmc, connection, ifname, ap, nsp, activate_connection_cb, &error)) {
		g_string_printf (nmc->return_text, _("Error: %s."),
		                 error ? error->message : _("unknown error"));
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		g_clear_error (&error);
		goto error;
	}

	/* Start progress indication */
	if (nmc->print_output == NMC_PRINT_PRETTY)
		progress_id = g_timeout_add (120, progress_cb, _("preparing"));

	g_free (line);
	return nmc->return_value;
error:
	nmc->should_wait = FALSE;
	g_free (line);
	return nmc->return_value;
}

static NMCResultCode
do_connection_down (NmCli *nmc, int argc, char **argv)
{
	NMActiveConnection *active;
	const GPtrArray *active_cons;
	char *line = NULL;
	char **arg_arr = NULL;
	char **arg_ptr = argv;
	int arg_num = argc;

	if (argc == 0) {
		if (nmc->ask) {
			line = nmc_get_user_input (_("Connection (name, UUID, or path): "));
			nmc_string_to_arg_array (line, "", &arg_arr, &arg_num);
			arg_ptr = arg_arr;
		}
		if (arg_num == 0) {
			g_string_printf (nmc->return_text, _("Error: No connection specified."));
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto error;
		}
	}

	/* create NMClient */
	nmc->get_client (nmc);

	if (!nm_client_get_manager_running (nmc->client)) {
		g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
		nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		goto error;
	}

	/* Get active connections */
	active_cons = nm_client_get_active_connections (nmc->client);
	while (arg_num > 0) {
		const char *selector = NULL;

		if (   strcmp (*arg_ptr, "id") == 0
		    || strcmp (*arg_ptr, "uuid") == 0
		    || strcmp (*arg_ptr, "path") == 0
		    || strcmp (*arg_ptr, "apath") == 0) {

			selector = *arg_ptr;
			if (next_arg (&arg_num, &arg_ptr) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), selector);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
		}

		active = find_active_connection (active_cons, nmc->system_connections, selector, *arg_ptr);
		if (active) {
			nm_client_deactivate_connection (nmc->client, active);
		} else {
			g_string_printf (nmc->return_text, _("Error: '%s' is not an active connection."), *arg_ptr);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			goto error;
		}

		next_arg (&arg_num, &arg_ptr);
	}

	// FIXME: do something better then sleep()
	/* Don't quit immediatelly and give NM time to check our permissions */
	sleep (1);

error:
	nmc->should_wait = FALSE;
	g_strfreev (arg_arr);
	return nmc->return_value;
}

/*----------------------------------------------------------------------------*/

typedef struct NameItem {
	const char *name;
	const char *alias;
	const struct NameItem *settings;
	gboolean mandatory;
} NameItem;

static const NameItem nmc_ethernet_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet", NULL, TRUE  },
	{ NM_SETTING_802_1X_SETTING_NAME,     NULL,       NULL, FALSE },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_infiniband_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL, NULL, TRUE  },
	{ NM_SETTING_INFINIBAND_SETTING_NAME, NULL, NULL, TRUE  },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL, NULL, FALSE },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME, NULL, NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_wifi_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME,        NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRELESS_SETTING_NAME,          "wifi",     NULL, TRUE  },
	{ NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, "wifi-sec", NULL, FALSE },
	{ NM_SETTING_802_1X_SETTING_NAME,            NULL,       NULL, FALSE },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME,        NULL,       NULL, FALSE },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME,        NULL,       NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_wimax_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,   NULL, TRUE  },
	{ NM_SETTING_WIMAX_SETTING_NAME,      NULL,   NULL, TRUE  },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL,   NULL, FALSE },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME, NULL,   NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_gsm_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_GSM_SETTING_NAME,        NULL,       NULL, TRUE  },
	{ NM_SETTING_SERIAL_SETTING_NAME,     NULL,       NULL, FALSE },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_cdma_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_CDMA_SETTING_NAME,       NULL,       NULL, TRUE  },
	{ NM_SETTING_SERIAL_SETTING_NAME,     NULL,       NULL, FALSE },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_mobile_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,   NULL, TRUE  },
	{ NM_SETTING_SERIAL_SETTING_NAME,     NULL,   NULL, FALSE },
	{ NM_SETTING_PPP_SETTING_NAME,        NULL,   NULL, FALSE },
	{ NM_SETTING_GSM_SETTING_NAME,        NULL,   NULL, TRUE  },
	{ NM_SETTING_CDMA_SETTING_NAME,       NULL,   NULL, TRUE  },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL,   NULL, FALSE },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME, NULL,   NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_bluetooth_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,   NULL, TRUE  },
	{ NM_SETTING_BLUETOOTH_SETTING_NAME,  NULL,   NULL, TRUE  },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL,   NULL, FALSE },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME, NULL,   NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_adsl_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,   NULL, TRUE  },
	{ NM_SETTING_ADSL_SETTING_NAME,       NULL,   NULL, TRUE  },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL,   NULL, FALSE },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME, NULL,   NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_ppoe_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet", NULL, FALSE },
	{ NM_SETTING_PPPOE_SETTING_NAME,      NULL,       NULL, TRUE  },
	{ NM_SETTING_PPP_SETTING_NAME,        NULL,       NULL, FALSE },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_olpc_mesh_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,        NULL, TRUE  },
	{ NM_SETTING_OLPC_MESH_SETTING_NAME,  "olpc-mesh", NULL, TRUE  },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL,        NULL, FALSE },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME, NULL,        NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_vpn_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,   NULL, TRUE  },
	{ NM_SETTING_VPN_SETTING_NAME,        NULL,   NULL, TRUE  },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL,   NULL, FALSE },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME, NULL,   NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_vlan_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet", NULL, FALSE },
	{ NM_SETTING_VLAN_SETTING_NAME,       NULL,       NULL, TRUE  },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_bond_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_BOND_SETTING_NAME,       NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet", NULL, FALSE },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_team_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_TEAM_SETTING_NAME,       NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet", NULL, FALSE },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_bridge_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_BRIDGE_SETTING_NAME,     NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet", NULL, FALSE },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_bond_slave_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet", NULL, TRUE  },
	{ NM_SETTING_802_1X_SETTING_NAME,     NULL,       NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_team_slave_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet", NULL, TRUE  },
	{ NM_SETTING_TEAM_PORT_SETTING_NAME,  NULL,       NULL, TRUE  },
	{ NM_SETTING_802_1X_SETTING_NAME,     NULL,       NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_bridge_slave_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME,  NULL,       NULL, TRUE  },
	{ NM_SETTING_BRIDGE_PORT_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,       "ethernet", NULL, TRUE  },
	{ NM_SETTING_802_1X_SETTING_NAME,      NULL,       NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};


/* Available connection types */
static const NameItem nmc_valid_connection_types[] = {
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet",  nmc_ethernet_settings     },
	{ NM_SETTING_WIRELESS_SETTING_NAME,   "wifi",      nmc_wifi_settings         },
	{ NM_SETTING_WIMAX_SETTING_NAME,      NULL,        nmc_wimax_settings        },
	{ NM_SETTING_GSM_SETTING_NAME,        NULL,        nmc_gsm_settings          },
	{ NM_SETTING_CDMA_SETTING_NAME,       NULL,        nmc_cdma_settings         },
	{ NM_SETTING_INFINIBAND_SETTING_NAME, NULL,        nmc_infiniband_settings   },
	{ NM_SETTING_ADSL_SETTING_NAME,       NULL,        nmc_adsl_settings         },
	{ NM_SETTING_BLUETOOTH_SETTING_NAME,  NULL,        nmc_bluetooth_settings    },
	{ NM_SETTING_VPN_SETTING_NAME,        NULL,        nmc_vpn_settings          },
	{ NM_SETTING_OLPC_MESH_SETTING_NAME,  "olpc-mesh", nmc_olpc_mesh_settings    },
	{ NM_SETTING_VLAN_SETTING_NAME,       NULL,        nmc_vlan_settings         },
	{ NM_SETTING_BOND_SETTING_NAME,       NULL,        nmc_bond_settings         },
	{ NM_SETTING_TEAM_SETTING_NAME,       NULL,        nmc_team_settings         },
	{ NM_SETTING_BRIDGE_SETTING_NAME,     NULL,        nmc_bridge_settings       },
	{ "bond-slave",                       NULL,        nmc_bond_slave_settings   },
	{ "team-slave",                       NULL,        nmc_team_slave_settings   },
	{ "bridge-slave",                     NULL,        nmc_bridge_slave_settings },
	{ NULL, NULL, NULL }
};

/*
 * Return an alias for the 'name' if exists, else return the 'name'.
 * The returned string must not be freed.
 */
static const char *
get_name_alias (const char *name, const NameItem array[])
{
	const NameItem *iter = &array[0];

	if (!name)
		return NULL;

        while (iter && iter->name) {
		if (!strcmp (name, iter->name)) {
			if (iter->alias)
				return iter->alias;
			else
				return iter->name;
		}
		iter++;
	}
	return name;
}

/*
 * Construct a string with names and aliases from the array formatted as:
 * "name (alias), name, name (alias), name, name"
 *
 * Returns: string; the caller is responsible for freeing it.
 */
static char *
get_valid_options_string (const NameItem array[])
{
	const NameItem *iter = &array[0];
	GString *str;

	str = g_string_sized_new (150);
	while (iter && iter->name) {
		if (str->len)
			g_string_append (str, ", ");
		if (iter->alias)
			g_string_append_printf (str, "%s (%s)", iter->name, iter->alias);
		else
			g_string_append (str, iter->name);
		iter++;
	}
	return g_string_free (str, FALSE);
}

/*
 * Check if 'val' is valid string in either array->name or array->alias.
 * It accepts shorter string provided they are not ambiguous.
 * 'val' == NULL doesn't hurt.
 *
 * Returns: pointer to array->name string or NULL on failure.
 * The returned string must not be freed.
 */
static const char *
check_valid_name (const char *val, const NameItem array[], GError **error)
{
	const NameItem *iter;
	GPtrArray *tmp_arr;
	const char *str;
	GError *tmp_err = NULL;

	/* Create a temporary array that can be used in nmc_string_is_valid() */
	tmp_arr = g_ptr_array_sized_new (30);
	iter = &array[0];
	while (iter && iter->name) {
		g_ptr_array_add (tmp_arr, (gpointer) iter->name);
		if (iter->alias)
			g_ptr_array_add (tmp_arr, (gpointer) iter->alias);
		iter++;
	}
	g_ptr_array_add (tmp_arr, (gpointer) NULL);

	/* Check string validity */
	str = nmc_string_is_valid (val, (const char **) tmp_arr->pdata, &tmp_err);
	if (!str) {
		if (tmp_err->code == 1)
			g_propagate_error (error, tmp_err);
		else {
			/* We want to handle aliases, so construct own error message */
			char *err_str = get_valid_options_string (array);
			g_set_error (error, 1, 0, _("'%s' not among [%s]"),
			             val ? val : "", err_str);
			g_free (err_str);
			g_clear_error (&tmp_err);
		}
		g_ptr_array_free (tmp_arr, TRUE);
		return NULL;
	}

	/* Return a pointer to the found string in passed 'array' */
	iter = &array[0];
	while (iter && iter->name) {
		if (   (iter->name && g_strcmp0 (iter->name, str) == 0)
		    || (iter->alias && g_strcmp0 (iter->alias, str) == 0)) {
			g_ptr_array_free (tmp_arr, TRUE);
			return iter->name;
		}
		iter++;
	}
	/* We should not really come here */
	g_ptr_array_free (tmp_arr, TRUE);
	g_set_error (error, 1, 0, _("Unknown error"));
	return NULL;
}

static const NameItem *
get_valid_settings_array (const char *con_type)
{
	guint i, num;

	if (!con_type)
		return NULL;

	num = G_N_ELEMENTS (nmc_valid_connection_types);
        for (i = 0; i < num; i++) {
		if (!strcmp (con_type, nmc_valid_connection_types[i].name))
			return nmc_valid_connection_types[i].settings;
	}
	return NULL;
}

static gboolean
is_setting_mandatory (NMConnection *connection, NMSetting *setting)
{
	NMSettingConnection *s_con;
	const char *c_type;
	const NameItem *item;
	const char *name;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	c_type = nm_setting_connection_get_connection_type (s_con);

	name = nm_setting_get_name (setting);

	item = get_valid_settings_array (c_type);
	while (item && item->name) {
		if (!strcmp (name, item->name))
			return item->mandatory;
		item++;
	}
	return FALSE;
}

/*----------------------------------------------------------------------------*/

static gboolean
check_and_convert_mac (const char *mac,
                       GByteArray **mac_array,
                       int type,
                       const char *keyword,
                       GError **error)
{
	GByteArray *local_mac_array = NULL;
	g_return_val_if_fail (mac_array == NULL || *mac_array == NULL, FALSE);

	if (!mac)
		return TRUE;

	local_mac_array = nm_utils_hwaddr_atoba (mac, type);
	if (!local_mac_array) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: '%s': '%s' is not a valid %s MAC address."),
		             keyword, mac, type == ARPHRD_INFINIBAND ? _("InfiniBand") : _("Ethernet"));
		return FALSE;
	}

	if (mac_array)
		*mac_array = local_mac_array;
	else
		if (local_mac_array)
			g_byte_array_free (local_mac_array, TRUE);

	return TRUE;
}

static gboolean
check_and_convert_mtu (const char *mtu, guint32 *mtu_int, GError **error)
{
	unsigned long local_mtu_int;

	if (!mtu)
		return TRUE;

	if (!nmc_string_to_uint (mtu, TRUE, 0, G_MAXUINT32, &local_mtu_int)) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: 'mtu': '%s' is not a valid MTU."), mtu);
		return FALSE;
	}
	if (mtu_int)
		*mtu_int = (guint32) local_mtu_int;
	return TRUE;
}

static gboolean
check_infiniband_parent (const char *parent, GError **error)
{
	if (!parent)
		return TRUE;

	if (!nm_utils_iface_valid_name (parent)) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: 'parent': '%s' is not a valid interface name."), parent);
		return FALSE;
	}
	return TRUE;
}


static gboolean
check_infiniband_p_key (const char *p_key, guint32 *p_key_int, GError **error)
{
	unsigned long local_p_key_int;
	gboolean p_key_valid = FALSE;
	if (!p_key)
		return TRUE;

	if (!strncmp (p_key, "0x", 2))
		p_key_valid = nmc_string_to_uint_base (p_key + 2, 16, TRUE, 0, G_MAXUINT16, &local_p_key_int);
	else
		p_key_valid = nmc_string_to_uint (p_key, TRUE, 0, G_MAXUINT16, &local_p_key_int);
	if (!p_key_valid) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: 'p-key': '%s' is not a valid InfiniBand P_KEY."), p_key);
		return FALSE;
	}
	if (p_key_int)
		*p_key_int = (guint32) local_p_key_int;
	return TRUE;
}

static gboolean
check_infiniband_mode (const char *mode, GError **error)
{
	if (!mode)
		return TRUE;

	if (strcmp (mode, "datagram") && strcmp (mode, "connected")) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: 'mode': '%s' is not a valid InfiniBand transport mode [datagram, connected]."), mode);
		return FALSE;
	}
	return TRUE;
}

static gboolean
check_and_convert_vlan_flags (const char *flags, guint32 *flags_int, GError **error)
{
	unsigned long local_flags_int;

	if (!flags)
		return TRUE;

	if (!nmc_string_to_uint (flags, TRUE, 0, 7, &local_flags_int)) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: 'flags': '%s' is not valid; use <0-7>."), flags);
		return FALSE;
	}
	if (flags_int)
		*flags_int = (guint32) local_flags_int;
	return TRUE;
}

static gboolean
check_and_convert_vlan_prio_maps (const char *prio_map,
                                  NMVlanPriorityMap type,
                                  char ***prio_map_arr,
                                  GError **error)
{
	char **local_prio_map_arr;
	GError *local_err = NULL;

	if (!prio_map)
		return TRUE;

	if (!(local_prio_map_arr = nmc_vlan_parse_priority_maps (prio_map, type, &local_err))) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: '%s': '%s' is not valid; %s "),
		             type == NM_VLAN_INGRESS_MAP ? "ingress" : "egress",
		             prio_map, local_err->message);
		return FALSE;
	}

	if (prio_map_arr)
		*prio_map_arr = local_prio_map_arr;
	return TRUE;
}

static gboolean
add_ip4_address_to_connection (NMIP4Address *ip4addr, NMConnection *connection)
{
	NMSettingIP4Config *s_ip4;
	gboolean ret;

	if (!ip4addr)
		return TRUE;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (!s_ip4) {
		s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_ip4));
		g_object_set (s_ip4,
		              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
		              NULL);
	}
	ret = nm_setting_ip4_config_add_address (s_ip4, ip4addr);
	nm_ip4_address_unref (ip4addr);

	return ret;
}

static gboolean
add_ip6_address_to_connection (NMIP6Address *ip6addr, NMConnection *connection)
{
	NMSettingIP6Config *s_ip6;
	gboolean ret;

	if (!ip6addr)
		return TRUE;

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (!s_ip6) {
		s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_ip6));
		g_object_set (s_ip6,
		              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
		              NULL);
	}
	ret = nm_setting_ip6_config_add_address (s_ip6, ip6addr);
	nm_ip6_address_unref (ip6addr);

	return ret;
}

static char *
unique_master_iface_ifname (GSList *list,
                            const char *type,
                            const char *ifname_property,
                            const char *try_name)
{
	NMConnection *connection;
	NMSetting *setting;
	char *new_name;
	unsigned int num = 1;
	GSList *iterator = list;
	char *ifname_val = NULL;

	new_name = g_strdup (try_name);
	while (iterator) {
		connection = NM_CONNECTION (iterator->data);
		setting = nm_connection_get_setting_by_name (connection, type);
		if (!setting) {
			iterator = g_slist_next (iterator);
			continue;
		}

		g_object_get (setting, ifname_property, &ifname_val, NULL);
		if (g_strcmp0 (new_name, ifname_val) == 0) {
			g_free (new_name);
			new_name = g_strdup_printf ("%s%d", try_name, num++);
			iterator = list;
		} else
			iterator = g_slist_next (iterator);
		g_free (ifname_val);
	}
	return new_name;
}

static gboolean
bridge_prop_string_to_uint (const char *str,
                            const char *nmc_arg,
                            GType bridge_type,
                            const char *propname,
                            unsigned long *out_val,
                            GError **error)
{
	GParamSpecUInt *pspec;

	pspec = (GParamSpecUInt *) g_object_class_find_property (g_type_class_peek (bridge_type),
	                                                         propname);
	g_assert (G_IS_PARAM_SPEC_UINT (pspec));

	if (!nmc_string_to_uint (str, TRUE, pspec->minimum, pspec->maximum, out_val)) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: '%s': '%s' is not valid; use <%u-%u>."),
		             nmc_arg, str, pspec->minimum, pspec->maximum);
		return FALSE;
	}
	return TRUE;
}

static void
do_questionnaire_ethernet (gboolean ethernet, char **mtu, char **mac, char **cloned_mac)
{
	char *answer;
	gboolean answer_bool;
	gboolean once_more;
	GError *error = NULL;
	const char *type = ethernet ? _("ethernet") : _("Wi-Fi");

	/* Ask for optional arguments */
	printf (_("There are 3 optional arguments for '%s' connection type.\n"), type);;
	answer = nmc_get_user_input (_("Do you want to provide them? (yes/no) [yes] "));
	if (answer && (!nmc_string_to_bool (answer, &answer_bool, NULL) || !answer_bool)) {
		g_free (answer);
		return;
	}

	if (!*mtu) {
		do {
			*mtu = nmc_get_user_input (_("MTU [auto]: "));
			once_more = !check_and_convert_mtu (*mtu, NULL, &error);
			if (once_more) {
				printf ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mtu);
			}
		} while (once_more);
	}
	if (!*mac) {
		do {
			*mac = nmc_get_user_input (_("MAC [none]: "));
			once_more = !check_and_convert_mac (*mac, NULL, ARPHRD_ETHER, "mac", &error);
			if (once_more) {
				printf ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mac);
			}
		} while (once_more);
	}
	if (!*cloned_mac) {
		do {
			*cloned_mac = nmc_get_user_input (_("Cloned MAC [none]: "));
			once_more = !check_and_convert_mac (*cloned_mac, NULL, ARPHRD_ETHER, "cloned-mac", &error);
			if (once_more) {
				printf ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*cloned_mac);
			}
		} while (once_more);
	}

	g_free (answer);
	return;
}

static void
do_questionnaire_infiniband (char **mtu, char **mac, char **mode, char **parent, char **p_key)
{
	char *answer;
	gboolean answer_bool;
	gboolean once_more;
	GError *error = NULL;

	/* Ask for optional arguments */
	printf (_("There are 5 optional arguments for 'InfiniBand' connection type.\n"));
	answer = nmc_get_user_input (_("Do you want to provide them? (yes/no) [yes] "));
	if (answer && (!nmc_string_to_bool (answer, &answer_bool, NULL) || !answer_bool)) {
		g_free (answer);
		return;
	}

	if (!*mtu) {
		do {
			*mtu = nmc_get_user_input (_("MTU [auto]: "));
			once_more = !check_and_convert_mtu (*mtu, NULL, &error);
			if (once_more) {
				printf ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mtu);
			}
		} while (once_more);
	}
	if (!*mac) {
		do {
			*mac = nmc_get_user_input (_("MAC [none]: "));
			once_more = !check_and_convert_mac (*mac, NULL, ARPHRD_INFINIBAND, "mac", &error);
			if (once_more) {
				printf ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mac);
			}
		} while (once_more);
	}
	if (!*mode) {
		do {
			*mode = nmc_get_user_input (_("Transport mode (datagram or connected) [datagram]: "));
			if (!*mode)
				*mode = g_strdup ("datagram");
			once_more = !check_infiniband_mode (*mode, &error);
			if (once_more) {
				printf ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mode);
			}
		} while (once_more);
	}
	if (!*parent) {
		do {
			*parent = nmc_get_user_input (_("Parent interface [none]: "));
			once_more = !check_infiniband_parent (*parent, &error);
			if (once_more) {
				printf ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*parent);
			}
		} while (once_more);
	}
	if (!*p_key) {
		do {
			*p_key = nmc_get_user_input (_("P_KEY [none]: "));
			once_more = !check_infiniband_p_key (*p_key, NULL, &error);
			if (once_more) {
				printf ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*p_key);
			}
			/* If parent is specified, so has to be P_KEY */
			if (!once_more && *parent && !*p_key) {
				once_more = TRUE;
				printf (_("Error: 'p-key' is mandatory when 'parent' is specified.\n"));
			}
		} while (once_more);
	}

	g_free (answer);
	return;
}

static void
do_questionnaire_wifi (char **mtu, char **mac, char **cloned_mac)
{
	/* At present, the optional Wi-Fi arguments are the same as for ethernet. */
	return do_questionnaire_ethernet (FALSE, mtu, mac, cloned_mac);
}

static void
do_questionnaire_wimax (char **mac)
{
	char *answer;
	gboolean answer_bool;
	gboolean once_more;
	GError *error = NULL;

	/* Ask for optional 'wimax' arguments. */
	printf (_("There is 1 optional argument for 'WiMax' connection type.\n"));
	answer = nmc_get_user_input (_("Do you want to provide it? (yes/no) [yes] "));
	if (answer && (!nmc_string_to_bool (answer, &answer_bool, NULL) || !answer_bool)) {
		g_free (answer);
		return;
	}

	if (!*mac) {
		do {
			*mac = nmc_get_user_input (_("MAC [none]: "));
			once_more = !check_and_convert_mac (*mac, NULL, ARPHRD_ETHER, "mac", &error);
			if (once_more) {
				printf ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mac);
			}
		} while (once_more);
	}

	g_free (answer);
	return;
}

static void
do_questionnaire_mobile (char **user, char **password)
{
	char *answer;
	gboolean answer_bool;

	/* Ask for optional 'gsm' or 'cdma' arguments. */
	printf (_("There are 2 optional arguments for 'mobile broadband' connection type.\n"));
	answer = nmc_get_user_input (_("Do you want to provide them? (yes/no) [yes] "));
	if (answer && (!nmc_string_to_bool (answer, &answer_bool, NULL) || !answer_bool)) {
		g_free (answer);
		return;
	}

	if (!*user)
		*user = nmc_get_user_input (_("Username [none]: "));
	if (!*password)
		*password = nmc_get_user_input (_("Password [none]: "));

	g_free (answer);
	return;
}

static void
do_questionnaire_bluetooth (char **bt_type)
{
	char *answer;
	gboolean answer_bool;
	gboolean once_more;

	/* Ask for optional 'bluetooth' arguments. */
	printf (_("There is 1 optional argument for 'bluetooth' connection type.\n"));
	answer = nmc_get_user_input (_("Do you want to provide it? (yes/no) [yes] "));
	if (answer && (!nmc_string_to_bool (answer, &answer_bool, NULL) || !answer_bool)) {
		g_free (answer);
		return;
	}

	if (!*bt_type) {
		do {
			*bt_type = nmc_get_user_input (_("Bluetooth type (panu, dun-gsm or dun-cdma) [panu]: "));
			if (!*bt_type)
				*bt_type = g_strdup ("panu");
			once_more =    strcmp (*bt_type, NM_SETTING_BLUETOOTH_TYPE_DUN)
			            && strcmp (*bt_type, NM_SETTING_BLUETOOTH_TYPE_DUN"-gsm")
			            && strcmp (*bt_type, NM_SETTING_BLUETOOTH_TYPE_DUN"-cdma")
			            && strcmp (*bt_type, NM_SETTING_BLUETOOTH_TYPE_PANU);
			if (once_more) {
				printf (_("Error: 'bt-type': '%s' is not a valid bluetooth type.\n"), *bt_type);
				g_free (*bt_type);
			}
		} while (once_more);
	}

	g_free (answer);
	return;
}

static void
do_questionnaire_vlan (char **mtu, char **flags, char **ingress, char **egress)
{
	char *answer;
	gboolean answer_bool;
	gboolean once_more;
	GError *error = NULL;

	/* Ask for optional 'vlan' arguments. */
	printf (_("There are 4 optional arguments for 'VLAN' connection type.\n"));
	answer = nmc_get_user_input (_("Do you want to provide them? (yes/no) [yes] "));
	if (answer && (!nmc_string_to_bool (answer, &answer_bool, NULL) || !answer_bool)) {
		g_free (answer);
		return;
	}

	if (!*mtu) {
		do {
			*mtu = nmc_get_user_input (_("MTU [auto]: "));
			once_more = !check_and_convert_mtu (*mtu, NULL, &error);
			if (once_more) {
				printf ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mtu);
			}
		} while (once_more);
	}
	if (!*flags) {
		do {
			*flags = nmc_get_user_input (_("VLAN flags (<0-7>) [none]: "));
			once_more = !check_and_convert_vlan_flags (*flags, NULL, &error);
			if (once_more) {
				printf ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*flags);
			}
		} while (once_more);
	}
	if (!*ingress) {
		do {
			*ingress = nmc_get_user_input (_("Ingress priority maps [none]: "));
			once_more = !check_and_convert_vlan_prio_maps (*ingress, NM_VLAN_INGRESS_MAP, NULL, &error);
			if (once_more) {
				printf ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*ingress);
			}
		} while (once_more);
	}
	if (!*egress) {
		do {
			*egress = nmc_get_user_input (_("Egress priority maps [none]: "));
			once_more = !check_and_convert_vlan_prio_maps (*egress, NM_VLAN_EGRESS_MAP, NULL, &error);
			if (once_more) {
				printf ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*egress);
			}
		} while (once_more);
	}

	g_free (answer);
	return;
}

static void
do_questionnaire_bond (char **mode, char **primary, char **miimon,
                       char **downdelay, char **updelay,
                       char **arpinterval, char **arpiptarget)
{
	char *answer, *monitor_mode;
	gboolean answer_bool;
	unsigned long tmp;
	gboolean once_more;
	GError *error = NULL;

	/* Ask for optional 'bond' arguments. */
	printf (_("There are optional arguments for 'bond' connection type.\n"));
	answer = nmc_get_user_input (_("Do you want to provide them? (yes/no) [yes] "));
	if (answer && (!nmc_string_to_bool (answer, &answer_bool, NULL) || !answer_bool)) {
		g_free (answer);
		return;
	}

	if (!*mode) {
		const char *mode_tmp;
		do {
			*mode = nmc_get_user_input (_("Bonding mode [balance-rr]: "));
			if (!*mode)
				*mode = g_strdup ("balance-rr");
			mode_tmp = nmc_bond_validate_mode (*mode, &error);
			g_free (*mode);
			if (mode_tmp) {
				*mode = g_strdup (mode_tmp);
			} else {
				printf ("%s\n", error->message);
				g_clear_error (&error);
			}
		} while (!mode_tmp);
	}

	if (g_strcmp0 (*mode, "active-backup") == 0 && !*primary) {
		do {
			*primary = nmc_get_user_input (_("Bonding primary interface [none]: "));
			once_more = *primary && !nm_utils_iface_valid_name (*primary);
			if (once_more) {
				printf (_("Error: 'primary': '%s' is not a valid interface name.\n"),
				        *primary);
				g_free (*primary);
			}
		} while (once_more);
	}

	do {
		monitor_mode = nmc_get_user_input (_("Bonding monitoring mode (miimon or arp) [miimon]: "));
		if (!monitor_mode)
			monitor_mode = g_strdup ("miimon");
		once_more = strcmp (monitor_mode, "miimon") && strcmp (monitor_mode, "arp");
		if (once_more) {
			printf (_("Error: '%s' is not a valid monitoring mode; use '%s' or '%s'.\n"),
			        monitor_mode, "miimon", "arp");
			g_free (monitor_mode);
		}
	} while (once_more);

	if (strcmp (monitor_mode, "miimon") == 0) {
		if (!*miimon) {
			do {
				*miimon = nmc_get_user_input (_("Bonding miimon [100]: "));
				once_more = *miimon && !nmc_string_to_uint (*miimon, TRUE, 0, G_MAXUINT32, &tmp);
				if (once_more) {
					printf (_("Error: 'miimon': '%s' is not a valid number <0-%u>.\n"),
					        *miimon, G_MAXUINT32);
					g_free (*miimon);
				}
			} while (once_more);
		}
		if (!*downdelay) {
			do {
				*downdelay = nmc_get_user_input (_("Bonding downdelay [0]: "));
				once_more = *downdelay && !nmc_string_to_uint (*downdelay, TRUE, 0, G_MAXUINT32, &tmp);
				if (once_more) {
					printf (_("Error: 'downdelay': '%s' is not a valid number <0-%u>.\n"),
					        *downdelay, G_MAXUINT32);
					g_free (*downdelay);
				}
			} while (once_more);
		}
		if (!*updelay) {
			do {
				*updelay = nmc_get_user_input (_("Bonding updelay [0]: "));
				once_more = *updelay && !nmc_string_to_uint (*updelay, TRUE, 0, G_MAXUINT32, &tmp);
				if (once_more) {
					printf (_("Error: 'updelay': '%s' is not a valid number <0-%u>.\n"),
					        *updelay, G_MAXUINT32);
					g_free (*updelay);
				}
			} while (once_more);
		}
	} else {
		if (!*arpinterval) {
			do {
				*arpinterval = nmc_get_user_input (_("Bonding arp-interval [0]: "));
				once_more = *arpinterval && !nmc_string_to_uint (*arpinterval, TRUE, 0, G_MAXUINT32, &tmp);
				if (once_more) {
					printf (_("Error: 'arp-interval': '%s' is not a valid number <0-%u>.\n"),
					        *arpinterval, G_MAXUINT32);
					g_free (*arpinterval);
				}
			} while (once_more);
		}
		if (!*arpiptarget) {
			//FIXME: verify the string
			*arpiptarget = nmc_get_user_input (_("Bonding arp-ip-target [none]: "));
		}
	}

	g_free (answer);
	g_free (monitor_mode);
	return;
}

static void
do_questionnaire_bridge (char **stp, char **priority, char **fwd_delay,
                         char **hello_time, char **max_age, char **ageing_time)
{
	char *answer;
	gboolean answer_bool;
	unsigned long tmp;
	gboolean once_more;
	GError *error = NULL;

	/* Ask for optional 'bridge' arguments. */
	printf (_("There are 6 optional arguments for 'bridge' connection type.\n"));
	answer = nmc_get_user_input (_("Do you want to provide them? (yes/no) [yes] "));
	if (answer && (!nmc_string_to_bool (answer, &answer_bool, NULL) || !answer_bool)) {
		g_free (answer);
		return;
	}

	if (!*stp) {
		gboolean stp_bool;
		do {
			*stp = nmc_get_user_input (_("Enable STP (yes/no) [yes]: "));
			*stp = *stp ? *stp : g_strdup ("yes");
			once_more = !nmc_string_to_bool (*stp, &stp_bool, &error);
			if (once_more) {
				printf (_("Error: 'stp': '%s'.\n"), error->message);
				g_clear_error (&error);
				g_free (*stp);
			}
		} while (once_more);
	}
	if (!*priority) {
		do {
			*priority = nmc_get_user_input (_("STP priority [128]: "));
			*priority = *priority ? *priority : g_strdup ("128");
			once_more = !nmc_string_to_uint (*priority, TRUE, 0, G_MAXUINT16, &tmp);
			if (once_more) {
				printf (_("Error: 'priority': '%s' is not a valid number <0-%d>.\n"),
				        *priority, G_MAXUINT16);
				g_free (*priority);
			}
		} while (once_more);
	}
	if (!*fwd_delay) {
		do {
			*fwd_delay = nmc_get_user_input (_("Forward delay [15]: "));
			*fwd_delay = *fwd_delay ? *fwd_delay : g_strdup ("15");
			once_more = !nmc_string_to_uint (*fwd_delay, TRUE, 2, 30, &tmp);
			if (once_more) {
				printf (_("Error: 'forward-delay': '%s' is not a valid number <2-30>.\n"),
				        *fwd_delay);
				g_free (*fwd_delay);
			}
		} while (once_more);
	}

	if (!*hello_time) {
		do {
			*hello_time = nmc_get_user_input (_("Hello time [2]: "));
			*hello_time = *hello_time ? *hello_time : g_strdup ("2");
			once_more = !nmc_string_to_uint (*hello_time, TRUE, 1, 10, &tmp);
			if (once_more) {
				printf (_("Error: 'hello-time': '%s' is not a valid number <1-10>.\n"),
				        *hello_time);
				g_free (*hello_time);
			}
		} while (once_more);
	}
	if (!*max_age) {
		do {
			*max_age = nmc_get_user_input (_("Max age [20]: "));
			*max_age = *max_age ? *max_age : g_strdup ("20");
			once_more = !nmc_string_to_uint (*max_age, TRUE, 6, 40, &tmp);
			if (once_more) {
				printf (_("Error: 'max-age': '%s' is not a valid number <6-40>.\n"),
				        *max_age);
				g_free (*max_age);
			}
		} while (once_more);
	}
	if (!*ageing_time) {
		do {
			*ageing_time = nmc_get_user_input (_("MAC address ageing time [300]: "));
			*ageing_time = *ageing_time ? *ageing_time : g_strdup ("300");
			once_more = !nmc_string_to_uint (*ageing_time, TRUE, 0, 1000000, &tmp);
			if (once_more) {
				printf (_("Error: 'ageing-time': '%s' is not a valid number <0-1000000>.\n"),
				        *ageing_time);
				g_free (*ageing_time);
			}
		} while (once_more);
	}

	g_free (answer);
	return;
}

static void
do_questionnaire_bridge_slave (char **priority, char **path_cost, char **hairpin)
{
	char *answer;
	gboolean answer_bool;
	unsigned long tmp;
	gboolean once_more;
	GError *error = NULL;

	/* Ask for optional 'bridge-slave' arguments. */
	printf (_("There are 3 optional arguments for 'bridge-slave' connection type.\n"));
	answer = nmc_get_user_input (_("Do you want to provide them? (yes/no) [yes] "));
	if (answer && (!nmc_string_to_bool (answer, &answer_bool, NULL) || !answer_bool)) {
		g_free (answer);
		return;
	}

	if (!*priority) {
		do {
			*priority = nmc_get_user_input (_("Bridge port priority [32]: "));
			*priority = *priority ? *priority : g_strdup ("32");
			once_more = !bridge_prop_string_to_uint (*priority, "priority", NM_TYPE_SETTING_BRIDGE_PORT,
			                                         NM_SETTING_BRIDGE_PORT_PRIORITY, &tmp, &error);
			if (once_more) {
				printf ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*priority);
			}
		} while (once_more);
	}
	if (!*path_cost) {
		do {
			*path_cost = nmc_get_user_input (_("Bridge port STP path cost [100]: "));
			*path_cost = *path_cost ? *path_cost : g_strdup ("100");
			once_more = !bridge_prop_string_to_uint (*path_cost, "path-cost", NM_TYPE_SETTING_BRIDGE_PORT,
			                                         NM_SETTING_BRIDGE_PORT_PATH_COST, &tmp, &error);
			if (once_more) {
				printf ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*path_cost);
			}
		} while (once_more);
	}
	if (!*hairpin) {
		gboolean hairpin_bool;
		do {
			*hairpin = nmc_get_user_input (_("Hairpin (yes/no) [yes]: "));
			*hairpin = *hairpin ? *hairpin : g_strdup ("yes");
			once_more = !nmc_string_to_bool (*hairpin, &hairpin_bool, &error);
			if (once_more) {
				printf (_("Error: 'hairpin': '%s'.\n"), error->message);
				g_clear_error (&error);
				g_free (*hairpin);
			}
		} while (once_more);
	}

	g_free (answer);
	return;
}

static void
do_questionnaire_vpn (char **user)
{
	char *answer;
	gboolean answer_bool;

	/* Ask for optional 'vpn' arguments. */
	printf (_("There is 1 optional argument for 'VPN' connection type.\n"));
	answer = nmc_get_user_input (_("Do you want to provide it? (yes/no) [yes] "));
	if (answer && (!nmc_string_to_bool (answer, &answer_bool, NULL) || !answer_bool)) {
		g_free (answer);
		return;
	}

	if (!*user)
		*user = nmc_get_user_input (_("Username [none]: "));

	g_free (answer);
	return;
}

static void
do_questionnaire_olpc (char **channel, char **dhcp_anycast)
{
	char *answer;
	gboolean answer_bool;
	unsigned long tmp;
	gboolean once_more;
	GError *error = NULL;

	/* Ask for optional 'olpc' arguments. */
	printf (_("There are 2 optional arguments for 'OLPC Mesh' connection type.\n"));
	answer = nmc_get_user_input (_("Do you want to provide them? (yes/no) [yes] "));
	if (answer && (!nmc_string_to_bool (answer, &answer_bool, NULL) || !answer_bool)) {
		g_free (answer);
		return;
	}

	if (!*channel) {
		do {
			*channel = nmc_get_user_input (_("OLPC Mesh channel [1]: "));
			once_more = *channel && !nmc_string_to_uint (*channel, TRUE, 1, 13, &tmp);
			if (once_more) {
				printf (_("Error: 'channel': '%s' is not a valid number <1-13>.\n"),
				        *channel);
				g_free (*channel);
			}
		} while (once_more);
	}
	if (!*dhcp_anycast) {
		do {
			*dhcp_anycast = nmc_get_user_input (_("DHCP anycast MAC address [none]: "));
			once_more = !check_and_convert_mac (*dhcp_anycast, NULL, ARPHRD_ETHER, "dhcp-anycast", &error);
			if (once_more) {
				printf ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*dhcp_anycast);
			}
		} while (once_more);
	}

	g_free (answer);
	return;
}

static gboolean
split_address (char* str, char **ip, char **gw, char **rest)
{
	size_t n1, n2, n3, n4, n5;

	*ip = *gw = *rest = NULL;
	if (!str)
		return FALSE;

	n1 = strspn  (str,    " \t");
	n2 = strcspn (str+n1, " \t\0") + n1;
	n3 = strspn  (str+n2, " \t")   + n2;
	n4 = strcspn (str+n3, " \t\0") + n3;
	n5 = strspn  (str+n4, " \t")   + n4;

	str[n2] = str[n4] = '\0';
	*ip = str[n1] ? str + n1 : NULL;
	*gw = str[n3] ? str + n3 : NULL;
	*rest = str[n5] ? str + n5 : NULL;

	return TRUE;
}

static void
ask_for_ip_addresses (NMConnection *connection, int family)
{
	gboolean ip_loop;
	GError *error = NULL;
	char *str, *ip, *gw, *rest;
	const char *prompt;
	gboolean added;
	gpointer ipaddr;

	if (family == 4)
		prompt =_("IPv4 address (IP[/plen] [gateway]) [none]: ");
	else
		prompt =_("IPv6 address (IP[/plen] [gateway]) [none]: ");

	ip_loop = TRUE;
	do {
		str = nmc_get_user_input (prompt);
		split_address (str, &ip, &gw, &rest);
		if (ip) {
			if (family == 4)
				ipaddr = nmc_parse_and_build_ip4_address (ip, gw, &error);
			else
				ipaddr = nmc_parse_and_build_ip6_address (ip, gw, &error);
			if (ipaddr) {
				if (family == 4)
					added = add_ip4_address_to_connection ((NMIP4Address *) ipaddr, connection);
				else
					added = add_ip6_address_to_connection ((NMIP6Address *) ipaddr, connection);
				gw = gw ? gw : (family == 4) ? "0.0.0.0" : "::";
				if (added)
					printf (_("  Address successfully added: %s %s\n"), ip, gw);
				else
					printf (_("  Warning: address already present: %s %s\n"), ip, gw);
				if (rest)
					printf (_("  Warning: ignoring garbage at the end: '%s'\n"), rest);
			} else {
				g_prefix_error (&error, _("Error: "));
				printf ("%s\n", error->message);
				g_clear_error (&error);
			}
		} else
			ip_loop = FALSE;

		g_free (str);
	} while (ip_loop);
}

static void
do_questionnaire_ip (NMConnection *connection)
{
	char *answer;
	gboolean answer_bool;

	/* Ask for IP addresses */
	answer = nmc_get_user_input (_("Do you want to add IP addresses? (yes/no) [yes] "));
	if (answer && (!nmc_string_to_bool (answer, &answer_bool, NULL) || !answer_bool)) {
		g_free (answer);
		return;
	}

	printf (_("Press <Enter> to finish adding addresses.\n"));

	ask_for_ip_addresses (connection, 4);
	ask_for_ip_addresses (connection, 6);

	g_free (answer);
	return;
}

static gboolean
complete_connection_by_type (NMConnection *connection,
                             const char *con_type,
                             GSList *all_connections,
                             gboolean ask,
                             int argc,
                             char **argv,
                             GError **error)
{
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingInfiniband *s_infiniband;
	NMSettingWireless *s_wifi;
	NMSettingWimax *s_wimax;
	NMSettingGsm *s_gsm;
	NMSettingCdma *s_cdma;
	NMSettingBluetooth *s_bt;
	NMSettingVlan *s_vlan;
	NMSettingBond *s_bond;
	NMSettingTeam *s_team;
	NMSettingTeamPort *s_team_port;
	NMSettingBridge *s_bridge;
	NMSettingBridgePort *s_bridge_port;
	NMSettingVPN *s_vpn;
	NMSettingOlpcMesh *s_olpc_mesh;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	if (!strcmp (con_type, NM_SETTING_WIRED_SETTING_NAME)) {
		/* Build up the settings required for 'ethernet' */
		gboolean success = FALSE;
		const char *mtu_c = NULL;
		char *mtu = NULL;
		guint32 mtu_int = 0;
		const char *mac_c = NULL;
		char *mac = NULL;
		const char *cloned_mac_c = NULL;
		char *cloned_mac = NULL;
		GByteArray *array = NULL;
		GByteArray *cloned_array = NULL;
		nmc_arg_t exp_args[] = { {"mtu",        TRUE, &mtu_c,        FALSE},
		                         {"mac",        TRUE, &mac_c,        FALSE},
		                         {"cloned-mac", TRUE, &cloned_mac_c, FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		/* Also ask for all optional arguments if '--ask' is specified. */
		mtu = mtu_c ? g_strdup (mtu_c) : NULL;
		mac = mac_c ? g_strdup (mac_c) : NULL;
		cloned_mac = cloned_mac_c ? g_strdup (cloned_mac_c) : NULL;
		if (ask)
			do_questionnaire_ethernet (TRUE, &mtu, &mac, &cloned_mac);

		if (!check_and_convert_mtu (mtu, &mtu_int, error))
			goto cleanup_wired;
		if (!check_and_convert_mac (mac, &array, ARPHRD_ETHER, "mac", error))
			goto cleanup_wired;
		if (!check_and_convert_mac (cloned_mac, &cloned_array, ARPHRD_ETHER, "cloned-mac", error))
			goto cleanup_wired;

		/* Add ethernet setting */
		s_wired = (NMSettingWired *) nm_setting_wired_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wired));

		if (mtu)
			g_object_set (s_wired, NM_SETTING_WIRED_MTU, mtu_int, NULL);
		if (array)
			g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, array, NULL);
		if (cloned_array)
			g_object_set (s_wired, NM_SETTING_WIRED_CLONED_MAC_ADDRESS, cloned_array, NULL);

		success = TRUE;
cleanup_wired:
		g_free (mtu);
		g_free (mac);
		g_free (cloned_mac);
		if (array)
			g_byte_array_free (array, TRUE);
		if (cloned_array)
			g_byte_array_free (cloned_array, TRUE);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, NM_SETTING_INFINIBAND_SETTING_NAME)) {
		/* Build up the settings required for 'infiniband' */
		gboolean success = FALSE;
		const char *mtu_c = NULL;
		char *mtu = NULL;
		guint32 mtu_int = 0;
		const char *mac_c = NULL;
		char *mac = NULL;
		GByteArray *array = NULL;
		const char *mode_c = NULL;
		char *mode = NULL;
		const char *parent_c = NULL;
		char *parent = NULL;
		const char *p_key_c = NULL;
		char *p_key = NULL;
		guint32 p_key_int = 0;
		nmc_arg_t exp_args[] = { {"mtu",            TRUE, &mtu_c,    FALSE},
		                         {"mac",            TRUE, &mac_c,    FALSE},
		                         {"transport-mode", TRUE, &mode_c,   FALSE},
		                         {"parent",         TRUE, &parent_c, FALSE},
		                         {"p-key",          TRUE, &p_key_c,  FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		/* Also ask for all optional arguments if '--ask' is specified. */
		mtu = mtu_c ? g_strdup (mtu_c) : NULL;
		mac = mac_c ? g_strdup (mac_c) : NULL;
		mode = mode_c ? g_strdup (mode_c) : NULL;
		parent = parent_c ? g_strdup (parent_c) : NULL;
		p_key = p_key_c ? g_strdup (p_key_c) : NULL;
		if (ask)
			do_questionnaire_infiniband (&mtu, &mac, &mode, &parent, &p_key);

		if (!check_and_convert_mtu (mtu, &mtu_int, error))
			goto cleanup_ib;
		if (!check_and_convert_mac (mac, &array, ARPHRD_INFINIBAND, "mac", error))
			goto cleanup_ib;
		if (!check_infiniband_mode (mode, error))
			goto cleanup_ib;
		if (p_key) {
			if (!check_infiniband_p_key (p_key, &p_key_int, error))
				goto cleanup_ib;
			if (!check_infiniband_parent (parent, error))
				goto cleanup_ib;
		} else if (parent) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("Error: 'parent': not valid without 'p-key'."));
			goto cleanup_ib;
		}

		/* Add 'infiniband' setting */
		s_infiniband = (NMSettingInfiniband *) nm_setting_infiniband_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_infiniband));

		g_object_set (s_infiniband, NM_SETTING_INFINIBAND_TRANSPORT_MODE, mode ? mode : "datagram", NULL);
		if (mtu)
			g_object_set (s_infiniband, NM_SETTING_INFINIBAND_MTU, mtu_int, NULL);
		if (array) {
			g_object_set (s_infiniband, NM_SETTING_INFINIBAND_MAC_ADDRESS, array, NULL);
			g_byte_array_free (array, TRUE);
		}
		if (p_key)
			g_object_set (s_infiniband, NM_SETTING_INFINIBAND_P_KEY, p_key_int, NULL);
		if (parent)
			g_object_set (s_infiniband, NM_SETTING_INFINIBAND_PARENT, parent, NULL);


		success = TRUE;
cleanup_ib:
		g_free (mtu);
		g_free (mac);
		g_free (mode);
		g_free (parent);
		g_free (p_key);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, NM_SETTING_WIRELESS_SETTING_NAME)) {
		/* Build up the settings required for 'wifi' */
		gboolean success = FALSE;
		char *ssid_ask = NULL;
		const char *ssid = NULL;
		GByteArray *ssid_arr = NULL;
		const char *mtu_c = NULL;
		char *mtu = NULL;
		guint32 mtu_int = 0;
		const char *mac_c = NULL;
		char *mac = NULL;
		GByteArray *mac_array = NULL;
		const char *cloned_mac_c = NULL;
		char *cloned_mac = NULL;
		GByteArray *cloned_mac_array = NULL;
		nmc_arg_t exp_args[] = { {"ssid",       TRUE, &ssid,         !ask},
		                         {"mtu",        TRUE, &mtu_c,        FALSE},
		                         {"mac",        TRUE, &mac_c,        FALSE},
		                         {"cloned-mac", TRUE, &cloned_mac_c, FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (!ssid && ask)
			ssid = ssid_ask = nmc_get_user_input (_("SSID: "));
		if (!ssid) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'ssid' is required."));
			return FALSE;
		}

		/* Also ask for all optional arguments if '--ask' is specified. */
		mtu = mtu_c ? g_strdup (mtu_c) : NULL;
		mac = mac_c ? g_strdup (mac_c) : NULL;
		cloned_mac = cloned_mac_c ? g_strdup (cloned_mac_c) : NULL;
		if (ask)
			do_questionnaire_wifi (&mtu, &mac, &cloned_mac);

		if (!check_and_convert_mtu (mtu, &mtu_int, error))
			goto cleanup_wifi;
		if (!check_and_convert_mac (mac, &mac_array, ARPHRD_ETHER, "mac", error))
			goto cleanup_wifi;
		if (!check_and_convert_mac (cloned_mac, &cloned_mac_array, ARPHRD_ETHER, "cloned-mac", error))
			goto cleanup_wifi;

		/* Add wifi setting */
		s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wifi));

		ssid_arr = g_byte_array_sized_new (strlen (ssid));
		g_byte_array_append (ssid_arr, (const guint8 *) ssid, strlen (ssid));
		g_object_set (s_wifi, NM_SETTING_WIRELESS_SSID, ssid_arr, NULL);

		if (mtu)
			g_object_set (s_wifi, NM_SETTING_WIRELESS_MTU, mtu_int, NULL);
		if (mac_array)
			g_object_set (s_wifi, NM_SETTING_WIRELESS_MAC_ADDRESS, mac_array, NULL);
		if (cloned_mac_array)
			g_object_set (s_wifi, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, cloned_mac_array, NULL);

		success = TRUE;
cleanup_wifi:
		g_free (ssid_ask);
		g_free (mtu);
		g_free (mac);
		g_free (cloned_mac);
		if (ssid_arr)
			g_byte_array_free (ssid_arr, TRUE);
		if (mac_array)
			g_byte_array_free (mac_array, TRUE);
		if (cloned_mac_array)
			g_byte_array_free (cloned_mac_array, TRUE);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, NM_SETTING_WIMAX_SETTING_NAME)) {
		/* Build up the settings required for 'wimax' */
		gboolean success = FALSE;
		const char *nsp_name = NULL;
		char *nsp_name_ask = NULL;
		const char *mac_c = NULL;
		char *mac = NULL;
		GByteArray *mac_array = NULL;
		nmc_arg_t exp_args[] = { {"nsp", TRUE, &nsp_name, !ask},
		                         {"mac", TRUE, &mac_c,    FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (!nsp_name && ask)
			nsp_name = nsp_name_ask = nmc_get_user_input (_("WiMAX NSP name: "));
		if (!nsp_name) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'nsp' is required."));
			goto cleanup_wimax;
		}

		/* Also ask for all optional arguments if '--ask' is specified. */
		mac = mac_c ? g_strdup (mac_c) : NULL;
		if (ask)
			do_questionnaire_wimax (&mac);

		if (!check_and_convert_mac (mac, &mac_array, ARPHRD_ETHER, "mac", error))
			goto cleanup_wimax;

		/* Add 'wimax' setting */
		s_wimax = (NMSettingWimax *) nm_setting_wimax_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wimax));
		g_object_set (s_wimax, NM_SETTING_WIMAX_NETWORK_NAME, nsp_name, NULL);

		if (mac_array) {
			g_object_set (s_wimax, NM_SETTING_WIMAX_MAC_ADDRESS, mac_array, NULL);
			g_byte_array_free (mac_array, TRUE);
		}

		success = TRUE;
cleanup_wimax:
		g_free (nsp_name_ask);
		g_free (mac);
		if (!success)
			return FALSE;

	} else if (   !strcmp (con_type, NM_SETTING_GSM_SETTING_NAME)
	           || !strcmp (con_type, NM_SETTING_CDMA_SETTING_NAME)) {
		/* Build up the settings required for 'gsm' or 'cdma' mobile broadband */
		gboolean success = FALSE;
		const char *apn = NULL;
		char *apn_ask = NULL;
		const char *user_c = NULL;
		char *user = NULL;
		const char *password_c = NULL;
		char *password = NULL;
		gboolean is_gsm;
		int i = 0;
		nmc_arg_t gsm_args[] = { {NULL}, {NULL}, {NULL}, /* placeholders */
		                         {NULL} };

		is_gsm = !strcmp (con_type, NM_SETTING_GSM_SETTING_NAME);

		if (is_gsm)
			gsm_args[i++] = (nmc_arg_t) {"apn", TRUE, &apn, !ask};
		gsm_args[i++] = (nmc_arg_t) {"user",     TRUE, &user_c,     FALSE};
		gsm_args[i++] = (nmc_arg_t) {"password", TRUE, &password_c, FALSE};
		gsm_args[i++] = (nmc_arg_t) {NULL};

		if (!nmc_parse_args (gsm_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (!apn && ask && is_gsm)
			apn = apn_ask = nmc_get_user_input (_("APN: "));
		if (!apn && is_gsm) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'apn' is required."));
			goto cleanup_mobile;
		}

		/* Also ask for all optional arguments if '--ask' is specified. */
		user = user_c ? g_strdup (user_c) : NULL;
		password = password_c ? g_strdup (password_c) : NULL;
		if (ask)
			do_questionnaire_mobile (&user, &password);

		if (is_gsm) {
			g_object_set (s_con, NM_SETTING_CONNECTION_TYPE, NM_SETTING_GSM_SETTING_NAME, NULL);

			/* Add 'gsm' setting */
			s_gsm = (NMSettingGsm *) nm_setting_gsm_new ();
			nm_connection_add_setting (connection, NM_SETTING (s_gsm));
			g_object_set (s_gsm,
			              NM_SETTING_GSM_NUMBER, "*99#",
			              NM_SETTING_GSM_APN, apn,
			              NM_SETTING_GSM_USERNAME, user,
			              NM_SETTING_GSM_PASSWORD, password,
			              NULL);
			g_free (apn_ask);
		} else {
			g_object_set (s_con, NM_SETTING_CONNECTION_TYPE, NM_SETTING_CDMA_SETTING_NAME, NULL);

			/* Add 'cdma' setting */
			s_cdma = (NMSettingCdma *) nm_setting_cdma_new ();
			nm_connection_add_setting (connection, NM_SETTING (s_cdma));
			g_object_set (s_cdma,
			              NM_SETTING_CDMA_NUMBER, "#777",
			              NM_SETTING_CDMA_USERNAME, user,
			              NM_SETTING_CDMA_PASSWORD, password,
			              NULL);
		}

		success = TRUE;
cleanup_mobile:
		g_free (user);
		g_free (password);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, NM_SETTING_BLUETOOTH_SETTING_NAME)) {
		/* Build up the settings required for 'bluetooth' */
		gboolean success = FALSE;
		const char *addr = NULL;
		char *addr_ask = NULL;
		const char *bt_type_c = NULL;
		char *bt_type = NULL;
		GByteArray *array = NULL;
		nmc_arg_t exp_args[] = { {"addr",    TRUE, &addr,      !ask},
		                         {"bt-type", TRUE, &bt_type_c, FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (!addr && ask)
			addr = addr_ask = nmc_get_user_input (_("Bluetooth device address: "));
		if (!addr) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'addr' is required."));
			return FALSE;
		}
		if (!check_and_convert_mac (addr, &array, ARPHRD_ETHER, "addr", error))
			goto cleanup_bt;

		/* Also ask for all optional arguments if '--ask' is specified. */
		bt_type = bt_type_c ? g_strdup (bt_type_c) : NULL;
		if (ask)
			do_questionnaire_bluetooth (&bt_type);

		/* Default to 'panu' if bt-type is not provided. */
		if (!bt_type)
			bt_type = g_strdup (NM_SETTING_BLUETOOTH_TYPE_PANU);

		/* Add 'bluetooth' setting */
		s_bt = (NMSettingBluetooth *) nm_setting_bluetooth_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_bt));

		if (array) {
			g_object_set (s_bt, NM_SETTING_BLUETOOTH_BDADDR, array, NULL);
			g_byte_array_free (array, TRUE);
		}

		/* 'dun' type requires adding 'gsm' or 'cdma' setting */
		if (   !strcmp (bt_type, NM_SETTING_BLUETOOTH_TYPE_DUN)
		    || !strcmp (bt_type, NM_SETTING_BLUETOOTH_TYPE_DUN"-gsm")) {
			bt_type = g_strdup (NM_SETTING_BLUETOOTH_TYPE_DUN);
			s_gsm = (NMSettingGsm *) nm_setting_gsm_new ();
			nm_connection_add_setting (connection, NM_SETTING (s_gsm));
			g_object_set (s_gsm, NM_SETTING_GSM_NUMBER, "*99#", NULL);
//			g_object_set (s_gsm, NM_SETTING_GSM_APN, "FIXME", NULL;

		} else if (!strcmp (bt_type, NM_SETTING_BLUETOOTH_TYPE_DUN"-cdma")) {
			bt_type = g_strdup (NM_SETTING_BLUETOOTH_TYPE_DUN);
			s_cdma = (NMSettingCdma *) nm_setting_cdma_new ();
			nm_connection_add_setting (connection, NM_SETTING (s_cdma));
			g_object_set (s_cdma, NM_SETTING_CDMA_NUMBER, "#777", NULL);

		} else if (!strcmp (bt_type, NM_SETTING_BLUETOOTH_TYPE_PANU)) {
			/* no op */
		} else {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("Error: 'bt-type': '%s' not valid; use [%s, %s (%s), %s]."),
			             bt_type, NM_SETTING_BLUETOOTH_TYPE_PANU, NM_SETTING_BLUETOOTH_TYPE_DUN,
			             NM_SETTING_BLUETOOTH_TYPE_DUN"-gsm", NM_SETTING_BLUETOOTH_TYPE_DUN"-cdma");
			goto cleanup_bt;
		}
		g_object_set (s_bt, NM_SETTING_BLUETOOTH_TYPE, bt_type, NULL);

		success = TRUE;
cleanup_bt:
		g_free (addr_ask);
		g_free (bt_type);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, NM_SETTING_VLAN_SETTING_NAME)) {
		/* Build up the settings required for 'vlan' */
		gboolean success = FALSE;
		const char *ifname = NULL;
		const char *parent = NULL;
		char *parent_ask = NULL;
		const char *vlan_id = NULL;
		char *vlan_id_ask = NULL;
		unsigned long id = 0;
		const char *flags_c = NULL;
		char *flags = NULL;
		guint32 flags_int = 0;
		const char *ingress_c = NULL, *egress_c = NULL;
		char *ingress = NULL, *egress = NULL;
		char **ingress_arr = NULL, **egress_arr = NULL, **p;
		const char *mtu_c = NULL;
		char *mtu = NULL;
		guint32 mtu_int;
		GByteArray *addr_array = NULL;
		nmc_arg_t exp_args[] = { {"dev",     TRUE, &parent,    !ask},
		                         {"id",      TRUE, &vlan_id,   !ask},
		                         {"flags",   TRUE, &flags_c,   FALSE},
		                         {"ingress", TRUE, &ingress_c, FALSE},
		                         {"egress",  TRUE, &egress_c,  FALSE},
		                         {"mtu",     TRUE, &mtu_c,     FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (!parent && ask)
			parent = parent_ask = nmc_get_user_input (_("VLAN parent device or connection UUID: "));
		if (!parent) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'dev' is required."));
			return FALSE;
		}
		if (!vlan_id && ask)
			vlan_id = vlan_id_ask = nmc_get_user_input (_("VLAN ID <0-4095>: "));
		if (!vlan_id) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'id' is required."));
			goto cleanup_vlan;
		}
		if (vlan_id) {
			if (!nmc_string_to_uint (vlan_id, TRUE, 0, 4095, &id)) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'id': '%s' is not valid; use <0-4095>."),
				             vlan_id);
				goto cleanup_vlan;
			}
		}

		if (   !(addr_array = nm_utils_hwaddr_atoba (parent, ARPHRD_ETHER))
		    && !nm_utils_is_uuid (parent)
		    && !nm_utils_iface_valid_name (parent)) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("Error: 'dev': '%s' is neither UUID, interface name, nor MAC."),
			             parent);
			goto cleanup_vlan;
		}

		/* Also ask for all optional arguments if '--ask' is specified. */
		mtu = mtu_c ? g_strdup (mtu_c) : NULL;
		flags = flags_c ? g_strdup (flags_c) : NULL;
		ingress = ingress_c ? g_strdup (ingress_c) : NULL;
		egress = egress_c ? g_strdup (egress_c) : NULL;
		if (ask)
			do_questionnaire_vlan (&mtu, &flags, &ingress, &egress);

		/* ifname is taken from connection's ifname */
		ifname = nm_setting_connection_get_interface_name (s_con);

		if (!check_and_convert_mtu (mtu, &mtu_int, error))
			goto cleanup_vlan;
		if (!check_and_convert_vlan_flags (flags, &flags_int, error))
			goto cleanup_vlan;
		if (!check_and_convert_vlan_prio_maps (ingress, NM_VLAN_INGRESS_MAP, &ingress_arr, error))
			goto cleanup_vlan;
		if (!check_and_convert_vlan_prio_maps (egress, NM_VLAN_EGRESS_MAP, &egress_arr, error))
			goto cleanup_vlan;

		/* Add 'vlan' setting */
		s_vlan = (NMSettingVlan *) nm_setting_vlan_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_vlan));

		/* Add 'wired' setting if necessary */
		if (mtu || addr_array) {
			s_wired = (NMSettingWired *) nm_setting_wired_new ();
			nm_connection_add_setting (connection, NM_SETTING (s_wired));

			if (mtu)
				g_object_set (s_wired, NM_SETTING_WIRED_MTU, mtu_int, NULL);
			if (addr_array)
				g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, addr_array, NULL);
		}

		/* Set 'vlan' properties */
		if (!addr_array)
			g_object_set (s_vlan, NM_SETTING_VLAN_PARENT, parent, NULL);

		if (ifname)
			g_object_set (s_vlan, NM_SETTING_VLAN_INTERFACE_NAME, ifname, NULL);
		g_object_set (s_vlan, NM_SETTING_VLAN_ID, id, NULL);

		if (flags)
			g_object_set (s_vlan, NM_SETTING_VLAN_FLAGS, flags_int, NULL);
		for (p = ingress_arr; p && *p; p++)
			nm_setting_vlan_add_priority_str (s_vlan, NM_VLAN_INGRESS_MAP, *p);
		for (p = egress_arr; p && *p; p++)
			nm_setting_vlan_add_priority_str (s_vlan, NM_VLAN_EGRESS_MAP, *p);

		success = TRUE;
cleanup_vlan:
		g_free (mtu);
		g_free (flags);
		g_free (ingress);
		g_free (egress);
		if (addr_array)
			g_byte_array_free (addr_array, TRUE);
		g_free (parent_ask);
		g_free (vlan_id_ask);
		g_strfreev (ingress_arr);
		g_strfreev (egress_arr);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, NM_SETTING_BOND_SETTING_NAME)) {
		/* Build up the settings required for 'bond' */
		gboolean success = FALSE;
		char *bond_ifname = NULL;
		const char *ifname = NULL;
		const char *bond_mode_c = NULL;
		char *bond_mode = NULL;
		const char *bond_primary_c = NULL;
		char *bond_primary = NULL;
		const char *bond_miimon_c = NULL;
		char *bond_miimon = NULL;
		const char *bond_downdelay_c = NULL;
		char *bond_downdelay = NULL;
		const char *bond_updelay_c = NULL;
		char *bond_updelay = NULL;
		const char *bond_arpinterval_c = NULL;
		char *bond_arpinterval = NULL;
		const char *bond_arpiptarget_c = NULL;
		char *bond_arpiptarget = NULL;
		nmc_arg_t exp_args[] = { {"mode",          TRUE, &bond_mode_c,        FALSE},
		                         {"primary",       TRUE, &bond_primary_c,     FALSE},
		                         {"miimon",        TRUE, &bond_miimon_c,      FALSE},
		                         {"downdelay",     TRUE, &bond_downdelay_c,   FALSE},
		                         {"updelay",       TRUE, &bond_updelay_c,     FALSE},
		                         {"arp-interval",  TRUE, &bond_arpinterval_c, FALSE},
		                         {"arp-ip-target", TRUE, &bond_arpiptarget_c, FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		/* Also ask for all optional arguments if '--ask' is specified. */
		bond_mode = bond_mode_c ? g_strdup (bond_mode_c) : NULL;
		bond_primary = bond_primary_c ? g_strdup (bond_primary_c) : NULL;
		bond_miimon = bond_miimon_c ? g_strdup (bond_miimon_c) : NULL;
		bond_downdelay = bond_downdelay_c ? g_strdup (bond_downdelay_c) : NULL;
		bond_updelay = bond_updelay_c ? g_strdup (bond_updelay_c) : NULL;
		bond_arpinterval = bond_arpinterval_c ? g_strdup (bond_arpinterval_c) : NULL;
		bond_arpiptarget = bond_arpiptarget_c ? g_strdup (bond_arpiptarget_c) : NULL;
		if (ask)
			do_questionnaire_bond (&bond_mode, &bond_primary, &bond_miimon,
			                       &bond_downdelay, &bond_updelay,
			                       &bond_arpinterval, &bond_arpiptarget);

		/* Use connection's ifname as 'bond' ifname if exists, else generate one */
		ifname = nm_setting_connection_get_interface_name (s_con);
		if (!ifname)
			bond_ifname = unique_master_iface_ifname (all_connections,
			                                          NM_SETTING_BOND_SETTING_NAME,
			                                          NM_SETTING_BOND_INTERFACE_NAME,
			                                          "nm-bond");
		else
			bond_ifname = g_strdup (ifname);

		/* Add 'bond' setting */
		s_bond = (NMSettingBond *) nm_setting_bond_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_bond));

		/* Set bond options */
		g_object_set (s_bond, NM_SETTING_BOND_INTERFACE_NAME, bond_ifname, NULL);
		if (bond_mode) {
			GError *err = NULL;
			const char *bm;
			if (!(bm = nmc_bond_validate_mode (bond_mode, &err))) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'mode': %s."), err->message);
				g_clear_error (&err);
				goto cleanup_bond;
			}
			nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MODE, bm);
		}
		if (bond_primary) {
			if (!nm_utils_iface_valid_name (bond_primary)) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'primary': '%s' is not a valid interface name."),
				             bond_primary);
				goto cleanup_bond;
			}
			nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_PRIMARY, bond_primary);
		}
		if (bond_miimon)
			nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MIIMON, bond_miimon);
		if (bond_downdelay && strcmp (bond_downdelay, "0") != 0)
			nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY, bond_downdelay);
		if (bond_updelay && strcmp (bond_updelay, "0") != 0)
			nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_UPDELAY, bond_updelay);
		if (bond_arpinterval && strcmp (bond_arpinterval, "0") != 0)
			nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ARP_INTERVAL, bond_arpinterval);
		if (bond_arpiptarget)
			nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ARP_IP_TARGET, bond_arpiptarget);

		success = TRUE;
cleanup_bond:
		g_free (bond_ifname);
		g_free (bond_mode);
		g_free (bond_primary);
		g_free (bond_miimon);
		g_free (bond_downdelay);
		g_free (bond_updelay);
		g_free (bond_arpinterval);
		g_free (bond_arpiptarget);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, "bond-slave")) {
		/* Build up the settings required for 'bond-slave' */
		const char *master = NULL;
		char *master_ask = NULL;
		const char *type = NULL;
		nmc_arg_t exp_args[] = { {"master", TRUE, &master, !ask},
		                         {"type",   TRUE, &type,   FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, TRUE, &argc, &argv, error))
			return FALSE;

		if (!master && ask)
			master = master_ask = nmc_get_user_input (_("Bond master: "));
		if (!master) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'master' is required."));
			return FALSE;
		}

		if (type)
			printf (_("Warning: 'type' is currently ignored. "
			          "We only support ethernet slaves for now.\n"));

		/* Change properties in 'connection' setting */
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
		              NM_SETTING_CONNECTION_MASTER, master,
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BOND_SETTING_NAME,
		              NULL);

		/* Add ethernet setting */
		s_wired = (NMSettingWired *) nm_setting_wired_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wired));

		g_free (master_ask);

	} else if (!strcmp (con_type, NM_SETTING_TEAM_SETTING_NAME)) {
		/* Build up the settings required for 'team' */
		char *team_ifname = NULL;
		const char *ifname = NULL;
		const char *config = NULL;
		nmc_arg_t exp_args[] = { {"config", TRUE, &config, FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		/* Use connection's ifname as 'team' ifname if exists, else generate one */
		ifname = nm_setting_connection_get_interface_name (s_con);
		if (!ifname)
			team_ifname = unique_master_iface_ifname (all_connections,
			                                          NM_SETTING_TEAM_SETTING_NAME,
			                                          NM_SETTING_TEAM_INTERFACE_NAME,
			                                          "nm-team");
		else
			team_ifname = g_strdup (ifname);

		/* Add 'team' setting */
		s_team = (NMSettingTeam *) nm_setting_team_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_team));

		/* Set team options */
		g_object_set (s_team, NM_SETTING_TEAM_INTERFACE_NAME, team_ifname, NULL);
		if (config)
			g_object_set (s_team, NM_SETTING_TEAM_CONFIG, config, NULL);

		g_free (team_ifname);

	} else if (!strcmp (con_type, "team-slave")) {
		/* Build up the settings required for 'team-slave' */
		const char *master = NULL;
		char *master_ask = NULL;
		const char *type = NULL;
		const char *config = NULL;
		nmc_arg_t exp_args[] = { {"master", TRUE, &master, !ask},
		                         {"type",   TRUE, &type,   FALSE},
		                         {"config",  TRUE, &config,  FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, TRUE, &argc, &argv, error))
			return FALSE;

		if (!master && ask)
			master = master_ask = nmc_get_user_input (_("Team master: "));
		if (!master) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'master' is required."));
			return FALSE;
		}

		if (type)
			printf (_("Warning: 'type' is currently ignored. "
			          "We only support ethernet slaves for now.\n"));

		/* Add 'team-port' setting */
		s_team_port = (NMSettingTeamPort *) nm_setting_team_port_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_team_port));

		if (config)
			g_object_set (s_team_port, NM_SETTING_TEAM_PORT_CONFIG, config, NULL);

		/* Change properties in 'connection' setting */
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
		              NM_SETTING_CONNECTION_MASTER, master,
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_TEAM_SETTING_NAME,
		              NULL);

		/* Add ethernet setting */
		s_wired = (NMSettingWired *) nm_setting_wired_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wired));

		g_free (master_ask);

	} else if (!strcmp (con_type, NM_SETTING_BRIDGE_SETTING_NAME)) {
		/* Build up the settings required for 'bridge' */
		gboolean success = FALSE;
		char *bridge_ifname = NULL;
		const char *ifname = NULL;
		const char *stp_c = NULL;
		char *stp = NULL;
		const char *priority_c = NULL;
		char *priority = NULL;
		const char *fwd_delay_c = NULL;
		char *fwd_delay = NULL;
		const char *hello_time_c = NULL;
		char *hello_time = NULL;
		const char *max_age_c = NULL;
		char *max_age = NULL;
		const char *ageing_time_c = NULL;
		char *ageing_time = NULL;
		gboolean stp_bool;
		unsigned long stp_prio_int, fwd_delay_int, hello_time_int,
		              max_age_int, ageing_time_int;
		nmc_arg_t exp_args[] = { {"stp",           TRUE, &stp_c,         FALSE},
		                         {"priority",      TRUE, &priority_c,    FALSE},
		                         {"forward-delay", TRUE, &fwd_delay_c,   FALSE},
		                         {"hello-time",    TRUE, &hello_time_c,  FALSE},
		                         {"max-age",       TRUE, &max_age_c,     FALSE},
		                         {"ageing-time",   TRUE, &ageing_time_c, FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		/* Also ask for all optional arguments if '--ask' is specified. */
		stp = stp_c ? g_strdup (stp_c) : NULL;
		priority = priority_c ? g_strdup (priority_c) : NULL;
		fwd_delay = fwd_delay_c ? g_strdup (fwd_delay_c) : NULL;
		hello_time = hello_time_c ? g_strdup (hello_time_c) : NULL;
		max_age = max_age_c ? g_strdup (max_age_c) : NULL;
		ageing_time = ageing_time_c ? g_strdup (ageing_time_c) : NULL;
		if (ask)
			do_questionnaire_bridge (&stp, &priority, &fwd_delay, &hello_time,
			                         &max_age, &ageing_time);

		/* Use connection's ifname as 'bridge' ifname if exists, else generate one */
		ifname = nm_setting_connection_get_interface_name (s_con);
		if (!ifname)
			bridge_ifname = unique_master_iface_ifname (all_connections,
			                                            NM_SETTING_BRIDGE_SETTING_NAME,
			                                            NM_SETTING_BRIDGE_INTERFACE_NAME,
			                                            "nm-bridge");
		else
			bridge_ifname = g_strdup (ifname);

		if (stp) {
			GError *tmp_err = NULL;
			if (!nmc_string_to_bool (stp, &stp_bool, &tmp_err)) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'stp': %s."), tmp_err->message);
				g_clear_error (&tmp_err);
				goto cleanup_bridge;
			}
		}

		/* Add 'bond' setting */
		/* Must be done *before* bridge_prop_string_to_uint() so that the type is known */
		s_bridge = (NMSettingBridge *) nm_setting_bridge_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_bridge));

		if (priority)
			if (!bridge_prop_string_to_uint (priority, "priority", NM_TYPE_SETTING_BRIDGE,
			                                 NM_SETTING_BRIDGE_PRIORITY, &stp_prio_int, error))
				goto cleanup_bridge;
		if (fwd_delay)
			if (!bridge_prop_string_to_uint (fwd_delay, "forward-delay", NM_TYPE_SETTING_BRIDGE,
			                                 NM_SETTING_BRIDGE_FORWARD_DELAY, &fwd_delay_int, error))
				goto cleanup_bridge;
		if (hello_time)
			if (!bridge_prop_string_to_uint (hello_time, "hello-time", NM_TYPE_SETTING_BRIDGE,
			                                 NM_SETTING_BRIDGE_HELLO_TIME, &hello_time_int, error))
				goto cleanup_bridge;
		if (max_age)
			if (!bridge_prop_string_to_uint (max_age, "max-age", NM_TYPE_SETTING_BRIDGE,
			                                 NM_SETTING_BRIDGE_MAX_AGE, &max_age_int, error))
				goto cleanup_bridge;
		if (ageing_time)
			if (!bridge_prop_string_to_uint (ageing_time, "ageing-time", NM_TYPE_SETTING_BRIDGE,
			                                 NM_SETTING_BRIDGE_AGEING_TIME, &ageing_time_int, error))
				goto cleanup_bridge;

		/* Set bridge options */
		g_object_set (s_bridge, NM_SETTING_BRIDGE_INTERFACE_NAME, bridge_ifname, NULL);
		if (stp)
			g_object_set (s_bridge, NM_SETTING_BRIDGE_STP, stp_bool, NULL);
		if (priority)
			g_object_set (s_bridge, NM_SETTING_BRIDGE_PRIORITY, stp_prio_int, NULL);
		if (fwd_delay)
			g_object_set (s_bridge, NM_SETTING_BRIDGE_FORWARD_DELAY, fwd_delay_int, NULL);
		if (hello_time)
			g_object_set (s_bridge, NM_SETTING_BRIDGE_HELLO_TIME, hello_time_int, NULL);
		if (max_age)
			g_object_set (s_bridge, NM_SETTING_BRIDGE_MAX_AGE, max_age_int, NULL);
		if (ageing_time)
			g_object_set (s_bridge, NM_SETTING_BRIDGE_AGEING_TIME, ageing_time_int, NULL);

		success = TRUE;
cleanup_bridge:
		g_free (bridge_ifname);
		g_free (stp);
		g_free (priority);
		g_free (fwd_delay);
		g_free (hello_time);
		g_free (max_age);
		g_free (ageing_time);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, "bridge-slave")) {
		/* Build up the settings required for 'bridge-slave' */
		gboolean success = FALSE;
		const char *master = NULL;
		char *master_ask = NULL;
		const char *type = NULL;
		const char *priority_c = NULL;
		char *priority = NULL;
		const char *path_cost_c = NULL;
		char *path_cost = NULL;
		const char *hairpin_c = NULL;
		char *hairpin = NULL;
		unsigned long prio_int, path_cost_int;
		gboolean hairpin_bool;
		nmc_arg_t exp_args[] = { {"master",    TRUE, &master,      !ask},
		                         {"type",      TRUE, &type,        FALSE},
		                         {"priority",  TRUE, &priority_c,  FALSE},
		                         {"path-cost", TRUE, &path_cost_c, FALSE},
		                         {"hairpin",   TRUE, &hairpin_c,   FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, TRUE, &argc, &argv, error))
			return FALSE;

		if (!master && ask)
			master = master_ask = nmc_get_user_input (_("Bridge master: "));
		if (!master) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'master' is required."));
			return FALSE;
		}
		if (!nm_utils_is_uuid (master) && !nm_utils_iface_valid_name (master)) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("Error: 'master': '%s' is not valid UUID nor interface."),
			             master);
			goto cleanup_bridge_slave;
		}

		if (type)
			printf (_("Warning: 'type' is currently ignored. "
			          "We only support ethernet slaves for now.\n"));

		/* Add 'bridge-port' setting */
		/* Must be done *before* bridge_prop_string_to_uint() so that the type is known */
		s_bridge_port = (NMSettingBridgePort *) nm_setting_bridge_port_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_bridge_port));

		/* Also ask for all optional arguments if '--ask' is specified. */
		priority = priority_c ? g_strdup (priority_c) : NULL;
		path_cost = path_cost_c ? g_strdup (path_cost_c) : NULL;
		hairpin = hairpin_c ? g_strdup (hairpin_c) : NULL;
		if (ask)
			do_questionnaire_bridge_slave (&priority, &path_cost, &hairpin);

		if (priority)
			if (!bridge_prop_string_to_uint (priority, "priority", NM_TYPE_SETTING_BRIDGE_PORT,
			                                 NM_SETTING_BRIDGE_PORT_PRIORITY, &prio_int, error))
				goto cleanup_bridge_slave;
		if (path_cost)
			if (!bridge_prop_string_to_uint (path_cost, "path-cost", NM_TYPE_SETTING_BRIDGE_PORT,
			                                 NM_SETTING_BRIDGE_PORT_PATH_COST, &path_cost_int, error))
				goto cleanup_bridge_slave;
		if (hairpin) {
			GError *tmp_err = NULL;
			if (!nmc_string_to_bool (hairpin, &hairpin_bool, &tmp_err)) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'hairpin': %s."), tmp_err->message);
				g_clear_error (&tmp_err);
				goto cleanup_bridge_slave;
			}
		}

		/* Change properties in 'connection' setting */
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
		              NM_SETTING_CONNECTION_MASTER, master,
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BRIDGE_SETTING_NAME,
		              NULL);

		/* Add ethernet setting */
		s_wired = (NMSettingWired *) nm_setting_wired_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wired));

		if (priority)
			g_object_set (s_bridge_port, NM_SETTING_BRIDGE_PORT_PRIORITY, prio_int, NULL);
		if (path_cost)
			g_object_set (s_bridge_port, NM_SETTING_BRIDGE_PORT_PATH_COST, path_cost_int, NULL);
		if (hairpin)
			g_object_set (s_bridge_port, NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE, hairpin_bool, NULL);

		success = TRUE;
cleanup_bridge_slave:
		g_free (master_ask);
		g_free (priority);
		g_free (path_cost);
		g_free (hairpin);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, NM_SETTING_VPN_SETTING_NAME)) {
		/* Build up the settings required for 'vpn' */
		gboolean success = FALSE;
		const char *valid_vpns[] = { "openvpn", "vpnc", "pptp", "openconnect", "openswan", NULL };
		const char *vpn_type = NULL;
		char *vpn_type_ask = NULL;
		const char *user_c = NULL;
		char *user = NULL;
		const char *st;
		char *service_type = NULL;
		GError *tmp_err = NULL;
		nmc_arg_t exp_args[] = { {"vpn-type", TRUE, &vpn_type, !ask},
		                         {"user",     TRUE, &user_c,   FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (!vpn_type && ask)
			vpn_type = vpn_type_ask = nmc_get_user_input (_("VPN type: "));
		if (!vpn_type) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'vpn-type' is required."));
			goto cleanup_vpn;
		}

		/* Also ask for all optional arguments if '--ask' is specified. */
		user = user_c ? g_strdup (user_c) : NULL;
		if (ask)
			do_questionnaire_vpn (&user);

		if (!(st = nmc_string_is_valid (vpn_type, valid_vpns, &tmp_err))) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("Error: 'vpn-type': %s."), tmp_err->message);
			g_clear_error (&tmp_err);
			goto cleanup_vpn;
		}
		service_type = g_strdup_printf ("%s.%s", NM_DBUS_INTERFACE, st);

		/* Add 'vpn' setting */
		s_vpn = (NMSettingVPN *) nm_setting_vpn_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_vpn));

		g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, service_type, NULL);
		g_object_set (s_vpn, NM_SETTING_VPN_USER_NAME, user, NULL);

		success = TRUE;
cleanup_vpn:
		g_free (vpn_type_ask);
		g_free (service_type);
		g_free (user);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, NM_SETTING_OLPC_MESH_SETTING_NAME)) {
		/* Build up the settings required for 'olpc' */
		gboolean success = FALSE;
		char *ssid_ask = NULL;
		const char *ssid = NULL;
		GByteArray *ssid_arr;
		const char *channel_c = NULL;
		char *channel = NULL;
		unsigned long chan;
		const char *dhcp_anycast_c = NULL;
		char *dhcp_anycast = NULL;
		GByteArray *array = NULL;
		nmc_arg_t exp_args[] = { {"ssid",         TRUE, &ssid,           !ask},
		                         {"channel",      TRUE, &channel_c,      FALSE},
		                         {"dhcp-anycast", TRUE, &dhcp_anycast_c, FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (!ssid && ask)
			ssid = ssid_ask = nmc_get_user_input (_("SSID: "));
		if (!ssid) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'ssid' is required."));
			goto cleanup_olpc;
		}

		/* Also ask for all optional arguments if '--ask' is specified. */
		channel = channel_c ? g_strdup (channel_c) : NULL;
		dhcp_anycast = dhcp_anycast_c ? g_strdup (dhcp_anycast_c) : NULL;
		if (ask)
			do_questionnaire_olpc (&channel, &dhcp_anycast);

		if (channel) {
			if (!nmc_string_to_uint (channel, TRUE, 1, 13, &chan)) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'channel': '%s' is not valid; use <1-13>."),
				             channel);
				goto cleanup_olpc;
			}
		}
		if (!check_and_convert_mac (dhcp_anycast, &array, ARPHRD_ETHER, "dhcp-anycast", error))
			goto cleanup_olpc;

		/* Add OLPC mesh setting */
		s_olpc_mesh = (NMSettingOlpcMesh *) nm_setting_olpc_mesh_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_olpc_mesh));

		ssid_arr = g_byte_array_sized_new (strlen (ssid));
		g_byte_array_append (ssid_arr, (const guint8 *) ssid, strlen (ssid));
		g_object_set (s_olpc_mesh, NM_SETTING_OLPC_MESH_SSID, ssid_arr, NULL);
		if (channel)
			g_object_set (s_olpc_mesh, NM_SETTING_OLPC_MESH_CHANNEL, chan, NULL);
		else
			g_object_set (s_olpc_mesh, NM_SETTING_OLPC_MESH_CHANNEL, 1, NULL);
		if (array) {
			g_object_set (s_olpc_mesh, NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS, array, NULL);
			g_byte_array_free (array, TRUE);
		}
		g_byte_array_free (ssid_arr, TRUE);

		success = TRUE;
cleanup_olpc:
		g_free (ssid_ask);
		g_free (channel);
		g_free (dhcp_anycast);
		if (!success)
			return FALSE;

	} else {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: '%s' is not a valid connection type."),
		             con_type);
		return FALSE;
	}

	/* Read and add IP configuration */
	if (   strcmp (con_type, "bond-slave") != 0
	    && strcmp (con_type, "team-slave") != 0
	    && strcmp (con_type, "bridge-slave") != 0) {

		NMIP4Address *ip4addr = NULL;
		NMIP6Address *ip6addr = NULL;
		const char *ip4 = NULL, *gw4 = NULL, *ip6 = NULL, *gw6 = NULL;
		nmc_arg_t exp_args[] = { {"ip4", TRUE, &ip4, FALSE}, {"gw4", TRUE, &gw4, FALSE},
		                         {"ip6", TRUE, &ip6, FALSE}, {"gw6", TRUE, &gw6, FALSE},
		                         {NULL} };

		while (argc) {
			nmc_arg_t *p;

			/* reset 'found' flag */
			for (p = exp_args; p->name; p++)
				p->found = FALSE;

			ip4 = gw4 = ip6 = gw6 = NULL;

			if (!nmc_parse_args (exp_args, TRUE, &argc, &argv, error))
				return FALSE;

			/* coverity[dead_error_begin] */
			if (ip4) {
				ip4addr = nmc_parse_and_build_ip4_address (ip4, gw4, error);
				if (!ip4addr) {
					g_prefix_error (error, _("Error: "));
					return FALSE;
				}
				add_ip4_address_to_connection (ip4addr, connection);
			}

			/* coverity[dead_error_begin] */
			if (ip6) {
				ip6addr = nmc_parse_and_build_ip6_address (ip6, gw6, error);
				if (!ip6addr) {
					g_prefix_error (error, _("Error: "));
					return FALSE;
				}
				add_ip6_address_to_connection (ip6addr, connection);
			}
		}

		/* Ask for addresses if '--ask' is specified. */
		if (ask)
			do_questionnaire_ip (connection);
	}

	return TRUE;
}

static char *
unique_connection_name (GSList *list, const char *try_name)
{
	NMConnection *connection;
	const char *name;
	char *new_name;
	unsigned int num = 1;
	GSList *iterator = list;

	new_name = g_strdup (try_name);
	while (iterator) {
		connection = NM_CONNECTION (iterator->data);

		name = nm_connection_get_id (connection);
		if (g_strcmp0 (new_name, name) == 0) {
			g_free (new_name);
			new_name = g_strdup_printf ("%s-%d", try_name, num++);
			iterator = list;
		}
		iterator = g_slist_next (iterator);
	}
	return new_name;
}

typedef struct {
	NmCli *nmc;
	char *con_name;
} AddConnectionInfo;

static void
add_connection_cb (NMRemoteSettings *settings,
                   NMRemoteConnection *connection,
                   GError *error,
                   gpointer user_data)
{
	AddConnectionInfo *info = (AddConnectionInfo *) user_data;
	NmCli *nmc = info->nmc;

	if (error) {
		g_string_printf (nmc->return_text,
		                 _("Error: Failed to add '%s' connection: (%d) %s"),
		                 info->con_name, error->code, error->message);
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
	} else {
		printf (_("Connection '%s' (%s) successfully added.\n"),
		        nm_connection_get_id (NM_CONNECTION (connection)),
		        nm_connection_get_uuid (NM_CONNECTION (connection)));
	}

	g_free (info->con_name);
	g_free (info);
	quit ();
}

static NMCResultCode
do_connection_add (NmCli *nmc, int argc, char **argv)
{
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	char *uuid;
	char *default_name = NULL;
	const char *type = NULL;
	char *type_ask = NULL;
	const char *con_name = NULL;
	const char *autoconnect = NULL;
	gboolean auto_bool = TRUE;
	const char *ifname = NULL;
	char *ifname_ask = NULL;
	gboolean ifname_mandatory = TRUE;
	AddConnectionInfo *info = NULL;
	const char *setting_name;
	GError *error = NULL;
	nmc_arg_t exp_args[] = { {"type",        TRUE, &type,        !nmc->ask},
	                         {"con-name",    TRUE, &con_name,    FALSE},
	                         {"autoconnect", TRUE, &autoconnect, FALSE},
	                         {"ifname",      TRUE, &ifname,      FALSE},
	                         {NULL} };

	nmc->return_value = NMC_RESULT_SUCCESS;

	if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, &error)) {
		g_string_assign (nmc->return_text, error->message);
		nmc->return_value = error->code;
		g_clear_error (&error);
		goto error;
	}

	if (!type && nmc->ask) {
		char *types_tmp = get_valid_options_string (nmc_valid_connection_types);
		printf ("Valid types: [%s]\n", types_tmp);
		type = type_ask = nmc_get_user_input (_("Connection type: "));
		g_free (types_tmp);
	}
	if (!type) {
		g_string_printf (nmc->return_text, _("Error: 'type' argument is required."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}

	if (!(setting_name = check_valid_name (type, nmc_valid_connection_types, &error))) {
		g_string_printf (nmc->return_text, _("Error: invalid connection type; %s."),
		                 error->message);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		g_clear_error (&error);
		goto error;
	}
	if (autoconnect) {
		GError *tmp_err = NULL;
		if (!nmc_string_to_bool (autoconnect, &auto_bool, &tmp_err)) {
			g_string_printf (nmc->return_text, _("Error: 'autoconnect': %s."),
			                 tmp_err->message);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			g_clear_error (&tmp_err);
			goto error;
		}
	}

	/* ifname is mandatory for all connection types except virtual ones (bond, team, bridge, vlan) */
	if (   strcmp (type, NM_SETTING_BOND_SETTING_NAME) == 0
	    || strcmp (type, NM_SETTING_TEAM_SETTING_NAME) == 0
	    || strcmp (type, NM_SETTING_BRIDGE_SETTING_NAME) == 0
	    || strcmp (type, NM_SETTING_VLAN_SETTING_NAME) == 0)
		ifname_mandatory = FALSE;

	if (!ifname && ifname_mandatory && nmc->ask)
		ifname = ifname_ask = nmc_get_user_input (_("Interface name [*]: "));
	if (!ifname && ifname_mandatory)
		ifname = ifname_ask = g_strdup ("*");

	if (ifname) {
		if (!nm_utils_iface_valid_name (ifname) && strcmp (ifname, "*") != 0) {
			g_string_printf (nmc->return_text,
			                 _("Error: 'ifname': '%s' is not a valid interface nor '*'."),
			                 ifname);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto error;
		}
		/* Special value of '*' means no specific interface name */
		if (strcmp (ifname, "*") == 0)
			ifname = NULL;
	}

	/* Create a new connection object */
	connection = nm_connection_new ();

	/* Build up the 'connection' setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	uuid = nm_utils_uuid_generate ();
	if (con_name)
		default_name = g_strdup (con_name);
	else {
		char *try_name = ifname ?
		                     g_strdup_printf ("%s-%s", get_name_alias (setting_name, nmc_valid_connection_types), ifname)
		                   : g_strdup (get_name_alias (setting_name, nmc_valid_connection_types));
		default_name = unique_connection_name (nmc->system_connections, try_name);
		g_free (try_name);
	}
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, default_name,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, setting_name,
	              NM_SETTING_CONNECTION_AUTOCONNECT, auto_bool,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, ifname,
	              NULL);
	g_free (uuid);
	g_free (default_name);
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	if (!complete_connection_by_type (connection,
	                                  setting_name,
	                                  nmc->system_connections,
	                                  nmc->ask,
	                                  argc,
	                                  argv,
	                                  &error)) {
		g_string_assign (nmc->return_text, error->message);
		nmc->return_value = error->code;
		g_clear_error (&error);
		goto error;
	}

	nmc->should_wait = TRUE;

	info = g_malloc0 (sizeof (AddConnectionInfo));
	info->nmc = nmc;
	info->con_name = g_strdup (nm_connection_get_id (connection));

	/* Tell the settings service to add the new connection */
	nm_remote_settings_add_connection (nmc->system_settings,
	                                   connection,
	                                   add_connection_cb,
	                                   info);

	if (connection)
		g_object_unref (connection);

	return nmc->return_value;

error:
	if (connection)
		g_object_unref (connection);
	g_free (type_ask);
	g_free (ifname_ask);

	nmc->should_wait = FALSE;
	return nmc->return_value;
}


/*----------------------------------------------------------------------------*/

typedef char *CPFunction ();
typedef char **CPPFunction ();
/* History entry struct copied from libreadline's history.h */
typedef struct _hist_entry {
	char *line;
	char *timestamp;
	char *data;
} HIST_ENTRY;

typedef char *  (*ReadLineFunc)     (const char *);
typedef void    (*AddHistoryFunc)   (const char *);
typedef HIST_ENTRY** (*HistoryListFunc)  (void);
typedef int     (*RlInsertTextFunc) (char *);
typedef char ** (*RlCompletionMatchesFunc) (char *, CPFunction *);

typedef struct {
	ReadLineFunc readline_func;
	AddHistoryFunc add_history_func;
	HistoryListFunc history_list_func;
	RlInsertTextFunc rl_insert_text_func;
	void **rl_startup_hook_x;
	RlCompletionMatchesFunc completion_matches_func;
	void **rl_attempted_completion_function_x;
	void **rl_completion_entry_function_x;
	char **rl_line_buffer_x;
	char **rl_prompt_x;
	int *rl_attempted_completion_over_x;
	int *rl_completion_append_character_x;
	const char **rl_completer_word_break_characters_x;
	void (*rl_free_line_state_func) (void);
	void (*rl_cleanup_after_signal_func) (void);
} EditLibSymbols;

static EditLibSymbols edit_lib_symbols;
static char *pre_input_deftext;

static int
set_deftext (void)
{
	if (   pre_input_deftext
	    && edit_lib_symbols.rl_insert_text_func
	    && edit_lib_symbols.rl_startup_hook_x) {
		edit_lib_symbols.rl_insert_text_func (pre_input_deftext);
		g_free (pre_input_deftext);
		pre_input_deftext = NULL;
		*edit_lib_symbols.rl_startup_hook_x = NULL;
	}
	return 0;
}

static char *
gen_func_basic (char *text, int state, const char **words)
{
	static int list_idx, len;
	const char *name;

	if (!state) {
		list_idx = 0;
		len = strlen (text);
	}

	/* Return the next name which partially matches one from the 'words' list. */
	while ((name = words[list_idx])) {
		list_idx++;

		if (strncmp (name, text, len) == 0)
			return g_strdup (name);
	}
	return NULL;
}

static char *
gen_nmcli_cmds_menu (char *text, int state)
{
	const char *words[] = { "goto", "set", "remove", "describe", "print", "verify",
	                        "save", "activate", "back", "help", "quit", "nmcli",
	                        NULL };
	return gen_func_basic (text, state, words);
}

static char *
gen_nmcli_cmds_submenu (char *text, int state)
{
	const char *words[] = { "set", "add", "change", "remove", "describe",
	                        "print", "back", "help", "quit",
	                        NULL };
	return gen_func_basic (text, state, words);
}

static char *
gen_cmd_nmcli (char *text, int state)
{
	const char *words[] = { "status-line", "save-confirmation", "prompt-color", NULL };
	return gen_func_basic (text, state, words);
}

static char *
gen_cmd_nmcli_prompt_color (char *text, int state)
{
	const char *words[] = { "0", "1", "2", "3", "4", "5", "6", "7", "8", NULL };
	return gen_func_basic (text, state, words);
}

static char *
gen_func_bool_values (char *text, int state)
{
	const char *words[] = { "yes", "no", NULL };
	return gen_func_basic (text, state, words);
}

static char *
gen_cmd_verify0 (char *text, int state)
{
	const char *words[] = { "all", NULL };
	return gen_func_basic (text, state, words);
}

static char *
gen_cmd_print2 (char *text, int state)
{
	const char *words[] = { "setting", "connection", "all", NULL };
	return gen_func_basic (text, state, words);
}

static char *
gen_connection_types (char *text, int state)
{
	static int list_idx, len;
	const char *c_type, *a_type;

	if (!state) {
		list_idx = 0;
		len = strlen (text);
	}

	while (nmc_valid_connection_types[list_idx].name) {
		a_type = nmc_valid_connection_types[list_idx].alias;
		c_type = nmc_valid_connection_types[list_idx].name;
		list_idx++;
		if (a_type && !strncmp (text, a_type, len))
			return g_strdup (a_type);
		if (c_type && !strncmp (text, c_type, len))
			return g_strdup (c_type);
	}

	return NULL;
}

static char *
gen_setting_names (char *text, int state)
{
	static int list_idx, len;
	const char *s_name, *a_name;
	const NameItem *valid_settings_arr;

	if (!state) {
		list_idx = 0;
		len = strlen (text);
	}

	valid_settings_arr = get_valid_settings_array (nmc_tab_completion.con_type);
	if (!valid_settings_arr)
		return NULL;
	while (valid_settings_arr[list_idx].name) {
		a_name = valid_settings_arr[list_idx].alias;
		s_name = valid_settings_arr[list_idx].name;
		list_idx++;
		if (len == 0 && a_name)
			return g_strdup_printf ("%s (%s)", s_name, a_name);
		if (a_name && !strncmp (text, a_name, len))
			return g_strdup (a_name);
		if (s_name && !strncmp (text, s_name, len))
			return g_strdup (s_name);
	}
	return NULL;
}

static char *
gen_property_names (char *text, int state)
{
	NMSetting *setting = NULL;
	char **valid_props = NULL;
	char *ret = NULL;
	char *line = g_strdup (*edit_lib_symbols.rl_line_buffer_x);
	const char *setting_name;
	char **strv = NULL;
	const NameItem *valid_settings_arr;
	const char *p1;

	/* Try to get the setting from 'line' - setting_name.property */
	p1 = strchr (line, '.');
	if (p1) {
		while (p1 > line && !g_ascii_isspace (*p1))
			p1--;

		strv = g_strsplit (p1+1, ".", 2);

		valid_settings_arr = get_valid_settings_array (nmc_tab_completion.con_type);
		setting_name = check_valid_name (strv[0], valid_settings_arr, NULL);
		setting = nmc_setting_new_for_name (setting_name);
	} else {
		/* Else take the current setting, if any */
		setting = nmc_tab_completion.setting ? g_object_ref (nmc_tab_completion.setting) : NULL;
	}

	if (setting) {
		valid_props = nmc_setting_get_valid_properties (setting);
		ret = gen_func_basic (text, state, (const char **) valid_props);
	}

	g_free (line);
	g_strfreev (strv);
	g_strfreev (valid_props);
	if (setting)
		g_object_unref (setting);
	return ret;
}

static char *
gen_compat_devices (char *text, int state)
{
	int i, j = 0;
	const GPtrArray *devices;
	const char **compatible_devices;
	char *ret;

	devices = nm_client_get_devices (nmc_tab_completion.nmc->client);
	if (!devices || devices->len < 1)
		return NULL;

	compatible_devices = g_new (const char *, devices->len + 1);
	for (i = 0; i < devices->len; i++) {
		NMDevice *dev = g_ptr_array_index (devices, i);
		const char *ifname = nm_device_get_ip_iface (dev);
		NMDevice *device = NULL;
		const char *spec_object = NULL;

		if (find_device_for_connection (nmc_tab_completion.nmc, nmc_tab_completion.connection,
		                                ifname, NULL, NULL, &device, &spec_object, NULL)) {
			compatible_devices[j++] = ifname;
		}
	}
	compatible_devices[j] = NULL;

	ret = gen_func_basic (text, state, compatible_devices);

	g_free (compatible_devices);
	return ret;
}

typedef char * (*my_gen_func_ptr) (char *, int);
static my_gen_func_ptr
get_gen_func_cmd_nmcli (char *str)
{
	if (!str)
		return NULL;
	if (matches (str, "status-line") == 0)
		return gen_func_bool_values;
	if (matches (str, "save-confirmation") == 0)
		return gen_func_bool_values;
	if (matches (str, "prompt-color") == 0)
		return gen_cmd_nmcli_prompt_color;
	return NULL;
}

/*
 * Helper function parsing line for completion.
 * IN:
 *   line : the whole line to be parsed
 *   end  : the position of cursor in the line
 *   cmd  : command to match
 * OUT:
 *   cw_num    : is set to the word number being completed (1, 2, 3, 4).
 *   prev_word : returns the previous word (so that we have some context).
 *
 * Returns TRUE when the first word of the 'line' matches 'cmd'.
 *
 * Examples:
 * line="rem"              cmd="remove"   -> TRUE  cw_num=1
 * line="set con"          cmd="set"      -> TRUE  cw_num=2
 * line="go ipv4.method"   cmd="goto"     -> TRUE  cw_num=2
 * line="  des eth.mtu "   cmd="describe" -> TRUE  cw_num=3
 * line=" bla ipv4.method" cmd="goto"     -> FALSE
 */
static gboolean
should_complete_cmd (const char *line, int end, const char *cmd,
                     int *cw_num, char **prev_word)
{
	char *tmp;
	const char *word1, *word2, *word3;
	size_t n1, n2, n3, n4, n5, n6;
	gboolean word1_done, word2_done, word3_done;
	gboolean ret = FALSE;

	if (!line)
		return FALSE;

	tmp = g_strdup (line);

	n1 = strspn  (tmp,    " \t");
	n2 = strcspn (tmp+n1, " \t\0") + n1;
	n3 = strspn  (tmp+n2, " \t")   + n2;
	n4 = strcspn (tmp+n3, " \t\0") + n3;
	n5 = strspn  (tmp+n4, " \t")   + n4;
	n6 = strcspn (tmp+n5, " \t\0") + n5;

	word1_done = end > n2;
	word2_done = end > n4;
	word3_done = end > n6;
	tmp[n2] = tmp[n4] = tmp[n6] = '\0';

	word1 = tmp[n1] ? tmp + n1 : NULL;
	word2 = tmp[n3] ? tmp + n3 : NULL;
	word3 = tmp[n5] ? tmp + n5 : NULL;

	if (!word1_done) {
		if (cw_num)
			*cw_num = 1;
		if (prev_word)
			*prev_word = NULL;
	} else if (!word2_done) {
		if (cw_num)
			*cw_num = 2;
		if (prev_word)
			*prev_word = g_strdup (word1);
	} else if (!word3_done) {
		if (cw_num)
			*cw_num = 3;
		if (prev_word)
			*prev_word = g_strdup (word2);
	} else {
		if (cw_num)
			*cw_num = 4;
		if (prev_word)
			*prev_word = g_strdup (word3);
	}

	if (word1 && matches (word1, cmd) == 0)
		ret = TRUE;

	g_free (tmp);
	return ret;
}

/*
 * Attempt to complete on the contents of TEXT.  START and END show the
 * region of TEXT that contains the word to complete.  We can use the
 * entire line in case we want to do some simple parsing.  Return the
 * array of matches, or NULL if there aren't any.
 */
static char **
nmcli_editor_tab_completion (char *text, int start, int end)
{
	char **match_array = NULL;
	const char *line = *edit_lib_symbols.rl_line_buffer_x;
	const char *prompt = *edit_lib_symbols.rl_prompt_x;
	CPFunction *generator_func = NULL;
	gboolean copy_char;
	const char *p1;
	char *p2, *prompt_tmp;
	char *word = NULL;
	size_t n1;
	int num;

	/* Restore standard append character to space */
	*edit_lib_symbols.rl_completion_append_character_x = ' ';

	/* Filter out possible ANSI color escape sequences */
	p1 = prompt;
	p2 = prompt_tmp = g_strdup (prompt);
	copy_char = TRUE;
	while (*p1) {
		if (*p1 == '\33')
			copy_char = FALSE;
		if (copy_char)
			*p2++ = *p1;
		if (!copy_char && *p1 == 'm')
			copy_char = TRUE;
		p1++;
	}
	*p2 = '\0';

	/* Find the first non-space character */
	n1 = strspn (line, " \t");

	/* Choose the right generator function */
	if (strcmp (prompt_tmp, EDITOR_PROMPT_CON_TYPE) == 0)
		generator_func = gen_connection_types;
	else if (strcmp (prompt_tmp, EDITOR_PROMPT_SETTING) == 0)
		generator_func = gen_setting_names;
	else if (strcmp (prompt_tmp, EDITOR_PROMPT_PROPERTY) == 0)
		generator_func = gen_property_names;
	else if (g_str_has_prefix (prompt_tmp, "nmcli")) {
		if (!strchr (prompt_tmp, '.')) {
			int level = g_str_has_prefix (prompt_tmp, "nmcli>") ? 0 : 1;
			const char *dot = strchr (line, '.');

			/* Main menu  - level 0,1 */
			if (start == n1)
				generator_func = gen_nmcli_cmds_menu;
			else {
				if (should_complete_cmd (line, end, "goto", &num, NULL) && num <= 2) {
					if (level == 0 && (!dot || dot >= line + end))
						generator_func = gen_setting_names;
					else
						generator_func = gen_property_names;
				} else if (  (   should_complete_cmd (line, end, "set", &num, NULL)
				              || should_complete_cmd (line, end, "remove", &num, NULL)
				              || should_complete_cmd (line, end, "describe", &num, NULL))
				           && num <= 2) {
					if (level == 0 && (!dot || dot >= line + end)) {
						generator_func = gen_setting_names;
						*edit_lib_symbols.rl_completion_append_character_x = '.';
					} else
						generator_func = gen_property_names;
				} else if (should_complete_cmd (line, end, "nmcli", &num, &word)) {
					if (num < 3)
						generator_func = gen_cmd_nmcli;
					else if (num == 3)
						generator_func = get_gen_func_cmd_nmcli (word);
				} else if (   should_complete_cmd (line, end, "print", &num, NULL)
				           || should_complete_cmd (line, end, "verify", &num, NULL)) {
					if (num <= 2)
						generator_func = gen_cmd_verify0;
				} else if (should_complete_cmd (line, end, "activate", &num, NULL) && num <= 2) {
					generator_func = gen_compat_devices;
				} else if (should_complete_cmd (line, end, "help", &num, NULL) && num <= 2)
					generator_func = gen_nmcli_cmds_menu;
			}
		} else {
			/* Submenu - level 2 */
			if (start == n1)
				generator_func = gen_nmcli_cmds_submenu;
			else {
				if (should_complete_cmd (line, end, "print", &num, NULL) && num <= 2)
					generator_func = gen_cmd_print2;
				else if (should_complete_cmd (line, end, "help", &num, NULL) && num <= 2)
					generator_func = gen_nmcli_cmds_submenu;
			}
		}
	}

	if (generator_func)
		match_array = edit_lib_symbols.completion_matches_func (text, generator_func);

	/* Disable default filename completion */
	if (!match_array)
		*edit_lib_symbols.rl_attempted_completion_over_x = 1;

	g_free (prompt_tmp);
	g_free (word);
	return match_array;
}

static GModule *
load_cmd_line_edit_lib (void)
{
	GModule *module;
	char *lib_path;
	int i;
	static const char * const edit_lib_table[] = {
	    "libreadline.so.6", /* GNU Readline library version 6 - latest */
	    "libreadline.so.5", /* GNU Readline library version 5 - previous */
	    "libedit.so.0",     /* NetBSD Editline library port (http://www.thrysoee.dk/editline/) */
	};

	/* Try to load a library for line editing */
	for (i = 0; i < G_N_ELEMENTS (edit_lib_table); i++) {
		lib_path = g_module_build_path (NULL, edit_lib_table[i]);
		module = g_module_open (lib_path, G_MODULE_BIND_LOCAL);
		g_free (lib_path);
		if (module)
			break;
	}
	if (!module)
		return NULL;

	if (!g_module_symbol (module, "readline", (gpointer) (&edit_lib_symbols.readline_func)))
		goto error;
	if (!g_module_symbol (module, "add_history", (gpointer) (&edit_lib_symbols.add_history_func)))
		goto error;
	if (!g_module_symbol (module, "history_list", (gpointer) (&edit_lib_symbols.history_list_func)))
		goto error;
	if (!g_module_symbol (module, "rl_insert_text", (gpointer) (&edit_lib_symbols.rl_insert_text_func)))
		goto error;
	if (!g_module_symbol (module, "rl_startup_hook", (gpointer) (&edit_lib_symbols.rl_startup_hook_x)))
		goto error;
	if (!g_module_symbol (module, "rl_attempted_completion_function",
	                      (gpointer) (&edit_lib_symbols.rl_attempted_completion_function_x)))
		goto error;
	if (!g_module_symbol (module, "completion_matches",
	                      (gpointer) (&edit_lib_symbols.completion_matches_func)))
		goto error;
	if (!g_module_symbol (module, "rl_line_buffer",
	                      (gpointer) (&edit_lib_symbols.rl_line_buffer_x)))
		goto error;
	if (!g_module_symbol (module, "rl_prompt",
	                      (gpointer) (&edit_lib_symbols.rl_prompt_x)))
		goto error;
	if (!g_module_symbol (module, "rl_attempted_completion_over",
	                      (gpointer) (&edit_lib_symbols.rl_attempted_completion_over_x)))
		goto error;
	if (!g_module_symbol (module, "rl_completion_append_character",
	                      (gpointer) (&edit_lib_symbols.rl_completion_append_character_x)))
		goto error;
	if (!g_module_symbol (module, "rl_completer_word_break_characters",
	                      (gpointer) (&edit_lib_symbols.rl_completer_word_break_characters_x)))
		goto error;
	if (!g_module_symbol (module, "rl_free_line_state",
	                      (gpointer) (&edit_lib_symbols.rl_free_line_state_func)))
		goto error;
	if (!g_module_symbol (module, "rl_cleanup_after_signal",
	                      (gpointer) (&edit_lib_symbols.rl_cleanup_after_signal_func)))
		goto error;

	/* Set a pointer to an alternative function to create matches */
	*edit_lib_symbols.rl_attempted_completion_function_x = (CPPFunction *) nmcli_editor_tab_completion;

	/* Use ' ' and '.' as word break characters */
	*edit_lib_symbols.rl_completer_word_break_characters_x = ". ";

	return module;
error:
	g_module_close (module);
	return NULL;
}

void
nmc_cleanup_readline (void)
{
	if (edit_lib_symbols.rl_free_line_state_func)
		edit_lib_symbols.rl_free_line_state_func ();
	if (edit_lib_symbols.rl_cleanup_after_signal_func)
		edit_lib_symbols.rl_cleanup_after_signal_func ();
}

static char *
readline_x (const char *prompt)
{
	char *str;

	if (edit_lib_symbols.readline_func) {
		str = edit_lib_symbols.readline_func (prompt);
		/* Return NULL, not empty string */
		if (str && *str == '\0') {
			g_free (str);
			str = NULL;
		}
	} else
		str = nmc_get_user_input (prompt);

	if (edit_lib_symbols.add_history_func && str && *str)
		edit_lib_symbols.add_history_func (str);

	return str;
}


#define NMCLI_EDITOR_HISTORY ".nmcli-history"

static void
load_history_cmds (const char *uuid)
{
	GKeyFile *kf;
	char *filename;
	char **keys;
	char *line;
	size_t i;
	GError *err = NULL;

	/* Nothing to do if readline library is not used */
	if (!edit_lib_symbols.add_history_func)
		return;

	filename = g_build_filename (g_get_home_dir (), NMCLI_EDITOR_HISTORY, NULL);
	kf = g_key_file_new ();
	if (!g_key_file_load_from_file (kf, filename, G_KEY_FILE_KEEP_COMMENTS, &err)) {
		if (err->code == G_KEY_FILE_ERROR_PARSE)
			printf ("Warning: %s parse error: %s\n", filename, err->message);
		g_key_file_free (kf);
		g_free (filename);
		return;
	}
	keys = g_key_file_get_keys (kf, uuid, NULL, NULL);
	for (i = 0; keys && keys[i]; i++) {
		line = g_key_file_get_string (kf, uuid, keys[i], NULL);
		if (line && *line)
			edit_lib_symbols.add_history_func (line);
		g_free (line);
	}
	g_strfreev (keys);
	g_key_file_free (kf);
	g_free (filename);
}

static void
save_history_cmds (const char *uuid)
{
	HIST_ENTRY **hist = NULL;
	GKeyFile *kf;
	char *filename;
	size_t i;
	char *key;
	char *data;
	gsize len = 0;
	GError *err = NULL;

	if (edit_lib_symbols.history_list_func)
		hist = edit_lib_symbols.history_list_func();

	if (hist) {
		filename = g_build_filename (g_get_home_dir (), NMCLI_EDITOR_HISTORY, NULL);
		kf = g_key_file_new ();
		if (!g_key_file_load_from_file (kf, filename, G_KEY_FILE_KEEP_COMMENTS, &err)) {
			if (   err->code != G_FILE_ERROR_NOENT
			    && err->code != G_KEY_FILE_ERROR_NOT_FOUND) {
				printf ("Warning: %s parse error: %s\n", filename, err->message);
				g_key_file_free (kf);
				g_free (filename);
				g_clear_error (&err);
				return;
			}
			g_clear_error (&err);
		}

		/* Remove previous history group and save new history entries */
		g_key_file_remove_group (kf, uuid, NULL);
		for (i = 0; hist[i]; i++)
		{
			key = g_strdup_printf ("%zd", i);
			g_key_file_set_string (kf, uuid, key, hist[i]->line);
			g_free (key);
		}

		/* Write history to file */
		data = g_key_file_to_data (kf, &len, NULL);
		if (data) {
			g_file_set_contents (filename, data, len, NULL);
			g_free (data);
		}
		g_key_file_free (kf);
		g_free (filename);
	}
}

/*----------------------------------------------------------------------------*/

static void
editor_show_connection (NMConnection *connection, NmCli *nmc)
{
	nmc->print_output = NMC_PRINT_PRETTY;
	nmc->multiline_output = TRUE;
	nmc->escape_values = 0;

	/* Remove any previous data */
	nmc_empty_output_fields (nmc);

	nmc_connection_detail (connection, nmc);
}

static void
editor_show_setting (NMSetting *setting, NmCli *nmc)
{
	printf (_("['%s' setting values]\n"),
	        nm_setting_get_name (setting));

	nmc->multiline_output = TRUE;
	nmc->escape_values = 0;

	/* Remove any previous data */
	nmc_empty_output_fields (nmc);

	setting_details (setting, nmc);
}

typedef enum {
	NMC_EDITOR_MAIN_CMD_UNKNOWN = 0,
	NMC_EDITOR_MAIN_CMD_GOTO,
	NMC_EDITOR_MAIN_CMD_REMOVE,
	NMC_EDITOR_MAIN_CMD_SET,
	NMC_EDITOR_MAIN_CMD_DESCRIBE,
	NMC_EDITOR_MAIN_CMD_PRINT,
	NMC_EDITOR_MAIN_CMD_VERIFY,
	NMC_EDITOR_MAIN_CMD_SAVE,
	NMC_EDITOR_MAIN_CMD_ACTIVATE,
	NMC_EDITOR_MAIN_CMD_BACK,
	NMC_EDITOR_MAIN_CMD_HELP,
	NMC_EDITOR_MAIN_CMD_NMCLI,
	NMC_EDITOR_MAIN_CMD_QUIT,
} NmcEditorMainCmd;

static NmcEditorMainCmd
parse_editor_main_cmd (const char *cmd, char **cmd_arg)
{
	NmcEditorMainCmd editor_cmd = NMC_EDITOR_MAIN_CMD_UNKNOWN;
	char **vec;

	vec = nmc_strsplit_set (cmd, " \t", 2);
	if (g_strv_length (vec) < 1) {
		if (cmd_arg)
			*cmd_arg = NULL;
		return NMC_EDITOR_MAIN_CMD_UNKNOWN;
	}

	if (matches (vec[0], "goto") == 0)
		editor_cmd = NMC_EDITOR_MAIN_CMD_GOTO;
	else if (matches (vec[0], "remove") == 0)
		editor_cmd = NMC_EDITOR_MAIN_CMD_REMOVE;
	else if (matches (vec[0], "set") == 0)
		editor_cmd = NMC_EDITOR_MAIN_CMD_SET;
	else if (matches (vec[0], "describe") == 0)
		editor_cmd = NMC_EDITOR_MAIN_CMD_DESCRIBE;
	else if (matches (vec[0], "print") == 0)
		editor_cmd = NMC_EDITOR_MAIN_CMD_PRINT;
	else if (matches (vec[0], "verify") == 0)
		editor_cmd = NMC_EDITOR_MAIN_CMD_VERIFY;
	else if (matches (vec[0], "save") == 0)
		editor_cmd = NMC_EDITOR_MAIN_CMD_SAVE;
	else if (matches (vec[0], "activate") == 0)
		editor_cmd = NMC_EDITOR_MAIN_CMD_ACTIVATE;
	else if (matches (vec[0], "back") == 0)
		editor_cmd = NMC_EDITOR_MAIN_CMD_BACK;
	else if (matches (vec[0], "help") == 0 || strcmp (vec[0], "?") == 0)
		editor_cmd = NMC_EDITOR_MAIN_CMD_HELP;
	else if (matches (vec[0], "quit") == 0)
		editor_cmd = NMC_EDITOR_MAIN_CMD_QUIT;
	else if (matches (vec[0], "nmcli") == 0)
		editor_cmd = NMC_EDITOR_MAIN_CMD_NMCLI;

	/* set pointer to command argument */
	if (cmd_arg)
		*cmd_arg = vec[1] ? g_strstrip (g_strdup (vec[1])) : NULL;

	g_strfreev (vec);
	return editor_cmd;
}

static void
editor_main_usage (void)
{
	printf ("------------------------------------------------------------------------------\n");
	/* TRANSLATORS: do not translate command names and keywords before ::
	 *              However, you should translate terms enclosed in <>.
	 */
	printf (_("---[ Main menu ]---\n"
	          "goto     [<setting> | <prop>]        :: go to a setting or property\n"
	          "remove   <setting>[.<prop>] | <prop> :: remove setting or reset property value\n"
	          "set      [<setting>.<prop> <value>]  :: set property value\n"
	          "describe [<setting>.<prop>]          :: describe property\n"
	          "print    [all]                       :: print the connection\n"
	          "verify   [all]                       :: verify the connection\n"
	          "save                                 :: save the connection\n"
	          "activate [<ifname>] [/<ap>|<nsp>]    :: activate the connection\n"
	          "back                                 :: go one level up (back)\n"
	          "help/?   [<command>]                 :: print this help\n"
	          "nmcli    <conf-option> <value>       :: nmcli configuration\n"
	          "quit                                 :: exit nmcli\n"));
	printf ("------------------------------------------------------------------------------\n");
}

static void
editor_main_help (const char *command)
{
	if (!command)
		editor_main_usage ();
	else {
		/* detailed command descriptions */
		NmcEditorMainCmd cmd = parse_editor_main_cmd (command, NULL);

		switch (cmd) {
		case NMC_EDITOR_MAIN_CMD_GOTO:
			printf (_("goto <setting>[.<prop>] | <prop>  :: enter setting/property for editing\n\n"
			          "This command enters into a setting or property for editing it.\n\n"
			          "Examples: nmcli> goto connection\n"
			          "          nmcli connection> goto secondaries\n"
			          "          nmcli> goto ipv4.addresses\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_REMOVE:
			printf (_("remove <setting>[.<prop>]  :: remove setting or reset property value\n\n"
			          "This command removes an entire setting from the connection, or if a property\n"
			          "is given, resets that property to the default value.\n\n"
			          "Examples: nmcli> remove wifi-sec\n"
			          "          nmcli> remove eth.mtu\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_SET:
			printf (_("set [<setting>.<prop> <value>]  :: set property value\n\n"
			          "This command sets property value.\n\n"
			          "Example: nmcli> set con.id My connection\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_DESCRIBE:
			printf (_("describe [<setting>.<prop>]  :: describe property\n\n"
			          "Shows property description. You can consult nm-settings(5) "
			          "manual page to see all NM settings and properties.\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_PRINT:
			printf (_("print [all]  :: print setting or connection values\n\n"
			          "Shows current property or the whole connection.\n\n"
			          "Example: nmcli ipv4> print all\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_VERIFY:
			printf (_("verify [all]  :: verify setting or connection validity\n\n"
			          "Verifies whether the setting or connection is valid and can "
			          "be saved later. It indicates invalid values on error.\n\n"
			          "Examples: nmcli> verify\n"
			          "          nmcli bond> verify\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_SAVE:
			printf (_("save  :: save the connection\n\n"
			          "Sends the connection to NetworkManager that will save it.\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_ACTIVATE:
			printf (_("activate [<ifname>] [/<ap>|<nsp>]  :: activate the connection\n\n"
			          "Activates the connection.\n\n"
			          "Available options:\n"
			          "<ifname>    - device the connection will be activated on\n"
			          "/<ap>|<nsp> - AP (Wi-Fi) or NSP (WiMAX) (prepend with / when <ifname> is not specified)\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_BACK:
			printf (_("back  :: go to upper menu level\n\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_HELP:
			printf (_("help/? [<command>]  :: help for the nmcli commands\n\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_NMCLI:
			printf (_("nmcli [<conf-option> <value>]  :: nmcli configuration\n\n"
			          "Configures nmcli. The following options are available:\n"
			          "status-line yes | no        [default: no]\n"
			          "save-confirmation yes | no  [default: yes]\n"
			          "prompt-color <0-8>          [default: 0]\n"
			          "  0 = normal\n"
			          "  1 = \33[30mblack\33[0m\n"
			          "  2 = \33[31mred\33[0m\n"
			          "  3 = \33[32mgreen\33[0m\n"
			          "  4 = \33[33myellow\33[0m\n"
			          "  5 = \33[34mblue\33[0m\n"
			          "  6 = \33[35mmagenta\33[0m\n"
			          "  7 = \33[36mcyan\33[0m\n"
			          "  8 = \33[37mwhite\33[0m\n"
			          "\n"
			          "Examples: nmcli> nmcli status-line yes\n"
			          "          nmcli> nmcli save-confirmation no\n"
			          "          nmcli> nmcli prompt-color 3\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_QUIT:
			printf (_("quit  :: exit nmcli\n\n"
			          "This command exits nmcli. When the connection being edited "
			          "is not saved, the user is asked to confirm the action.\n"));
			break;
		default:
			printf (_("Unknown command: '%s'\n"), command);
			break;
		}
	}
}

typedef enum {
	NMC_EDITOR_SUB_CMD_UNKNOWN = 0,
	NMC_EDITOR_SUB_CMD_SET,
	NMC_EDITOR_SUB_CMD_ADD,
	NMC_EDITOR_SUB_CMD_CHANGE,
	NMC_EDITOR_SUB_CMD_REMOVE,
	NMC_EDITOR_SUB_CMD_DESCRIBE,
	NMC_EDITOR_SUB_CMD_PRINT,
	NMC_EDITOR_SUB_CMD_BACK,
	NMC_EDITOR_SUB_CMD_HELP,
	NMC_EDITOR_SUB_CMD_QUIT
} NmcEditorSubCmd;

static NmcEditorSubCmd
parse_editor_sub_cmd (const char *cmd, char **cmd_arg)
{
	NmcEditorSubCmd editor_cmd = NMC_EDITOR_SUB_CMD_UNKNOWN;
	char **vec;

	vec = nmc_strsplit_set (cmd, " \t", 2);
	if (g_strv_length (vec) < 1) {
		if (cmd_arg)
			*cmd_arg = NULL;
		return NMC_EDITOR_SUB_CMD_UNKNOWN;
	}

	if (matches (vec[0], "set") == 0)
		editor_cmd = NMC_EDITOR_SUB_CMD_SET;
	else if (matches (vec[0], "add") == 0)
		editor_cmd = NMC_EDITOR_SUB_CMD_ADD;
	else if (matches (vec[0], "change") == 0)
		editor_cmd = NMC_EDITOR_SUB_CMD_CHANGE;
	else if (matches (vec[0], "remove") == 0)
		editor_cmd = NMC_EDITOR_SUB_CMD_REMOVE;
	else if (matches (vec[0], "describe") == 0)
		editor_cmd = NMC_EDITOR_SUB_CMD_DESCRIBE;
	else if (matches (vec[0], "print") == 0)
		editor_cmd = NMC_EDITOR_SUB_CMD_PRINT;
	else if (matches (vec[0], "back") == 0)
		editor_cmd = NMC_EDITOR_SUB_CMD_BACK;
	else if (matches (vec[0], "help") == 0 || strcmp (vec[0], "?") == 0)
		editor_cmd = NMC_EDITOR_SUB_CMD_HELP;
	else if (matches (vec[0], "quit") == 0)
		editor_cmd = NMC_EDITOR_SUB_CMD_QUIT;

	/* set pointer to command argument */
	if (cmd_arg)
		*cmd_arg = g_strdup (vec[1]);

	g_strfreev (vec);
	return editor_cmd;
}

static void
editor_sub_help (void)
{
	printf ("------------------------------------------------------------------------------\n");
	/* TRANSLATORS: do not translate command names and keywords before ::
	 *              However, you should translate terms enclosed in <>.
	 */
	printf (_("---[ Property menu ]---\n"
	          "set      [<value>]               :: set new value\n"
	          "add      [<value>]               :: add new option to the property\n"
	          "change                           :: change current value\n"
	          "remove   [<index> | <option>]    :: delete the value\n"
	          "describe                         :: describe property\n"
	          "print    [setting | connection]  :: print property (setting/connection) value(s)\n"
	          "back                             :: go to upper level\n"
	          "help/?   [<command>]             :: print this help or command description\n"
	          "quit                             :: exit nmcli\n"));
	printf ("------------------------------------------------------------------------------\n");
}

static void
editor_sub_usage (const char *command)
{

	if (!command)
		editor_sub_help ();
	else {
		/* detailed command descriptions */
		NmcEditorSubCmd cmdsub = parse_editor_sub_cmd (command, NULL);

		switch (cmdsub) {
		case NMC_EDITOR_SUB_CMD_SET:
			printf (_("set [<value>]  :: set new value\n\n"
			          "This command sets provided <value> to this property\n"));
			break;
		case NMC_EDITOR_SUB_CMD_ADD:
			printf (_("add [<value>]  :: add new option to the property\n\n"
			          "This command add provided <value> to this property, if "
			          "the property is of a container type. For single-valued "
			          "properties it replaces the value (same as 'set').\n"));
			break;
		case NMC_EDITOR_SUB_CMD_CHANGE:
			printf (_("change  :: change current value\n\n"
			          "Displays current value and allows editing it.\n"));
			break;
		case NMC_EDITOR_SUB_CMD_REMOVE:
			printf (_("remove [<index>|<option>]  :: delete the value\n\n"
			          "Removes the property value (sets it to default).\n"));
			break;
		case NMC_EDITOR_SUB_CMD_DESCRIBE:
			printf (_("describe  :: describe property\n\n"
			          "Shows property description. You can consult nm-settings(5) "
			          "manual page to see all NM settings and properties.\n"));
			break;
		case NMC_EDITOR_SUB_CMD_PRINT:
			printf (_("print [property|setting|connection]  :: print property (setting, connection) value(s)\n\n"
			          "Shows property value. Providing an argument you can also display "
			          "values for the whole setting or connection.\n"));
			break;
		case NMC_EDITOR_SUB_CMD_BACK:
			printf (_("back  :: go to upper menu level\n\n"));
			break;
		case NMC_EDITOR_SUB_CMD_HELP:
			printf (_("help/? [<command>]  :: help for nmcli commands\n\n"));
			break;
		case NMC_EDITOR_SUB_CMD_QUIT:
			printf (_("quit  :: exit nmcli\n\n"
			          "This command exits nmcli. When the connection being edited "
			          "is not saved, the user is asked to confirm the action.\n"));
			break;
		default:
			printf (_("Unknown command: '%s'\n"), command);
			break;
		}
	}
}

/*----------------------------------------------------------------------------*/

typedef struct {
	NMDevice *device;
	NMActiveConnection *ac;
	guint monitor_id;
} MonitorACInfo;

static gboolean nmc_editor_cb_called;
static GError *nmc_editor_error;
static MonitorACInfo *nmc_editor_monitor_ac;
static GMutex nmc_editor_mutex;
static GCond nmc_editor_cond;

/*
 * Store 'error' to shared 'nmc_editor_error' and monitoring info to
 * 'nmc_editor_monitor_ac' and signal the condition so that
 * the 'editor-thread' thread could process that.
 */
static void
set_info_and_signal_editor_thread (GError *error, MonitorACInfo *monitor_ac_info)
{
	g_mutex_lock (&nmc_editor_mutex);
	nmc_editor_cb_called = TRUE;
	nmc_editor_error = error ? g_error_copy (error) : NULL;
	nmc_editor_monitor_ac = monitor_ac_info;
	g_cond_signal (&nmc_editor_cond);
	g_mutex_unlock (&nmc_editor_mutex);
}

static void
add_connection_editor_cb (NMRemoteSettings *settings,
                          NMRemoteConnection *connection,
                          GError *error,
                          gpointer user_data)
{
	set_info_and_signal_editor_thread (error, NULL);
}

static void
update_connection_editor_cb (NMRemoteConnection *connection,
                             GError *error,
                             gpointer user_data)
{
	set_info_and_signal_editor_thread (error, NULL);
}

static gboolean
progress_activation_editor_cb (gpointer user_data)
{
	MonitorACInfo *info = (MonitorACInfo *) user_data;
	NMDevice *device = info->device;
	NMActiveConnection *ac = info->ac;
	NMActiveConnectionState ac_state;
	NMDeviceState dev_state;

	if (!device || !ac)
		return FALSE;

	ac_state = nm_active_connection_get_state (ac);
	dev_state = nm_device_get_state (device);

	nmc_terminal_show_progress (nmc_device_state_to_string (dev_state));

	if (   ac_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED
	    || dev_state == NM_DEVICE_STATE_ACTIVATED) {
		nmc_terminal_erase_line ();
		printf (_("Connection successfully activated (D-Bus active path: %s)\n"),
		        nm_object_get_path (NM_OBJECT (ac)));
		return FALSE; /* we are done */
	} else if (   ac_state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED
	           || ac_state == NM_ACTIVE_CONNECTION_STATE_UNKNOWN) {
		nmc_terminal_erase_line ();
		printf (_("Error: Connection activation failed.\n"));
		return FALSE; /* we are done */
	}

	return TRUE;
}

static void
activate_connection_editor_cb (NMClient *client,
                               NMActiveConnection *active,
                               GError *error,
                               gpointer user_data)
{
	ActivateConnectionInfo *info = (ActivateConnectionInfo *) user_data;
	NMDevice *device = info->device;
	const GPtrArray *ac_devs;
	MonitorACInfo *monitor_ac_info = NULL;

	if (!error) {
		if (!device) {
			ac_devs = nm_active_connection_get_devices (active);
			device = ac_devs && ac_devs->len > 0 ? g_ptr_array_index (ac_devs, 0) : NULL;
		}
		if (device) {
			monitor_ac_info = g_malloc0 (sizeof (AddConnectionInfo));
			monitor_ac_info->device = device;
			monitor_ac_info->ac = active;
			monitor_ac_info->monitor_id = g_timeout_add (120, progress_activation_editor_cb, monitor_ac_info);
		}
	}
	set_info_and_signal_editor_thread (error, monitor_ac_info);
}

/*----------------------------------------------------------------------------*/

static void
print_property_description (NMSetting *setting, const char *prop_name)
{
	char *desc;

	desc = nmc_setting_get_property_desc (setting, prop_name);
	printf ("\n=== [%s] ===\n%s\n", prop_name, desc);
	g_free (desc);
}

static void
print_setting_description (NMSetting *setting)
{
	/* Show description of all properties */
	char **all_props;
	int i;

	all_props = nmc_setting_get_valid_properties (setting);
	printf (("<<< %s >>>\n"), nm_setting_get_name (setting));
	for (i = 0; all_props && all_props[i]; i++)
		print_property_description (setting, all_props[i]);
	g_strfreev (all_props);
}

static gboolean
connection_remove_setting (NMConnection *connection, NMSetting *setting)
{
	gboolean mandatory;

	mandatory = is_setting_mandatory (connection, setting);
	if (!mandatory) {
		nm_connection_remove_setting (connection, G_OBJECT_TYPE (setting));
		return TRUE;
	}
	printf (_("Error: setting '%s' is mandatory and cannot be removed.\n"),
	        nm_setting_get_name (setting));
	return FALSE;
}

static void
editor_show_status_line (NMConnection *connection, gboolean dirty)
{
	NMSettingConnection *s_con;
	const char *con_type, *con_id, *con_uuid;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	con_type = nm_setting_connection_get_connection_type (s_con);
	con_id = nm_connection_get_id (connection);
	con_uuid = nm_connection_get_uuid (connection);

	/* TRANSLATORS: status line in nmcli connection editor */
	printf (_("[ Connection type: %s | name: %s | UUID: %s | dirty: %s ]\n"),
	        con_type, con_id, con_uuid, dirty ? _("yes") : _("no"));
}

/*
 * Submenu for detailed property editing
 * Return: TRUE - continue;  FALSE - should quit
 */
static gboolean
property_edit_submenu (NmCli *nmc,
                       NMConnection *connection,
                       NMRemoteConnection *rem_con,
                       NMSetting *curr_setting,
                       const char *prop_name)
{
	NmcEditorSubCmd cmdsub;
	gboolean cmd_property_loop = TRUE;
	gboolean should_quit = FALSE;
	char *prop_val_user, *tmp_prompt;
	gboolean set_result;
	GError *tmp_err = NULL;
	char *prompt;
	gboolean dirty;
	GValue prop_g_value = G_VALUE_INIT;

	prompt = nmc_colorize (nmc->editor_prompt_color, "nmcli %s.%s> ",
	                       nm_setting_get_name (curr_setting), prop_name);

	while (cmd_property_loop) {
		char *cmd_property_user;
		char *cmd_property_arg;

		/* Connection is dirty? (not saved or differs from the saved) */
		dirty = !nm_connection_compare (connection,
		                                rem_con ? NM_CONNECTION (rem_con) : NULL,
		                                NM_SETTING_COMPARE_FLAG_EXACT);

		if (nmc->editor_status_line)
			editor_show_status_line (connection, dirty);

		cmd_property_user = readline_x (prompt);
		if (!cmd_property_user || *cmd_property_user == '\0')
			continue;
		cmdsub = parse_editor_sub_cmd (g_strstrip (cmd_property_user), &cmd_property_arg);

		switch (cmdsub) {
		case NMC_EDITOR_SUB_CMD_SET:
		case NMC_EDITOR_SUB_CMD_ADD:
			/* list, arrays,...: SET replaces the whole property value
			 *                   ADD adds the new value(s)
			 * single values:  : both SET and ADD sets the new value
			 */
			if (!cmd_property_arg) {
				tmp_prompt = g_strdup_printf (_("Enter '%s' value: "), prop_name);
				prop_val_user = readline_x (tmp_prompt);
				g_free (tmp_prompt);
			} else
				prop_val_user = g_strdup (cmd_property_arg);

			/* nmc_setting_set_property() only adds new value, thus we have to
			 * remove the original value and save it for error cases.
			 */
			if (cmdsub == NMC_EDITOR_SUB_CMD_SET) {
				nmc_property_get_gvalue (curr_setting, prop_name, &prop_g_value);
				nmc_property_set_default_value (curr_setting, prop_name);
			}

			set_result = nmc_setting_set_property (curr_setting, prop_name, prop_val_user, &tmp_err);
			g_free (prop_val_user);
			if (!set_result) {
				printf (_("Error: failed to set '%s' property: %s\n"), prop_name, tmp_err->message);
				g_clear_error (&tmp_err);
				if (cmdsub == NMC_EDITOR_SUB_CMD_SET)
					nmc_property_set_gvalue (curr_setting, prop_name, &prop_g_value);
			}
			if (G_IS_VALUE (&prop_g_value))
				g_value_unset (&prop_g_value);
			break;

		case NMC_EDITOR_SUB_CMD_CHANGE:
			*edit_lib_symbols.rl_startup_hook_x = set_deftext;
			pre_input_deftext = nmc_setting_get_property_out2in (curr_setting, prop_name, NULL);
			tmp_prompt = g_strdup_printf (_("Edit '%s' value: "), prop_name);
			prop_val_user = readline_x (tmp_prompt);

			nmc_property_get_gvalue (curr_setting, prop_name, &prop_g_value);
			nmc_property_set_default_value (curr_setting, prop_name);

			if (!nmc_setting_set_property (curr_setting, prop_name, prop_val_user, &tmp_err)) {
				printf (_("Error: failed to set '%s' property: %s\n"), prop_name, tmp_err->message);
				g_clear_error (&tmp_err);
				nmc_property_set_gvalue (curr_setting, prop_name, &prop_g_value);
			}
			g_free (prop_val_user);
			g_free (tmp_prompt);
			if (G_IS_VALUE (&prop_g_value))
				g_value_unset (&prop_g_value);
			break;

		case NMC_EDITOR_SUB_CMD_REMOVE:
			if (cmd_property_arg) {
				unsigned long val_int = G_MAXUINT32;
				char *option = NULL;

				if (!nmc_string_to_uint (cmd_property_arg, TRUE, 0, G_MAXUINT32, &val_int))
					option = g_strdup (cmd_property_arg);

				if (!nmc_setting_remove_property_option (curr_setting, prop_name,
				                                         option ? g_strstrip (option) : NULL,
				                                         (guint32) val_int,
				                                         &tmp_err)) {
					printf (_("Error: %s\n"), tmp_err->message);
					g_clear_error (&tmp_err);
				}
				g_free (option);
			} else {
				if (!nmc_setting_reset_property (curr_setting, prop_name, &tmp_err)) {
					printf (_("Error: failed to remove value of '%s': %s\n"), prop_name,
					        tmp_err->message);
					g_clear_error (&tmp_err);
				}
			}
			break;

		case NMC_EDITOR_SUB_CMD_DESCRIBE:
			/* Show property description */
			print_property_description (curr_setting, prop_name);
			break;

		case NMC_EDITOR_SUB_CMD_PRINT:
			/* Print current connection settings/properties */
			if (cmd_property_arg) {
				if (matches (cmd_property_arg, "setting") == 0)
					editor_show_setting (curr_setting, nmc);
				else if (   matches (cmd_property_arg, "connection") == 0
				         || matches (cmd_property_arg, "all") == 0)
					editor_show_connection (connection, nmc);
				else
					printf (_("Unknown command argument: '%s'\n"), cmd_property_arg);
			} else {
				char *prop_val =  nmc_setting_get_property (curr_setting, prop_name, NULL);
				printf ("%s: %s\n", prop_name, prop_val);
				g_free (prop_val);
			}
			break;

		case NMC_EDITOR_SUB_CMD_BACK:
			cmd_property_loop = FALSE;
			break;

		case NMC_EDITOR_SUB_CMD_HELP:
			editor_sub_usage (cmd_property_arg);
			break;

		case NMC_EDITOR_SUB_CMD_QUIT:
			if (dirty) {
				char *tmp_str;
				do {
					tmp_str = nmc_get_user_input (_("The connection is not saved. "
					                                "Do you really want to quit? [y/n]\n"));
				} while (!tmp_str);
				if (matches (tmp_str, "yes") == 0) {
					cmd_property_loop = FALSE;
					should_quit = TRUE;  /* we will quit nmcli */
				}
				g_free (tmp_str);
			} else {
				cmd_property_loop = FALSE;
				should_quit = TRUE;  /* we will quit nmcli */
			}
			break;

		case NMC_EDITOR_SUB_CMD_UNKNOWN:
		default:
			printf (_("Unknown command: '%s'\n"), cmd_property_user);
			break;
		}
		g_free (cmd_property_user);
		g_free (cmd_property_arg);
	}
	g_free (prompt);

	return !should_quit;
}

/*
 * Split 'str' in the following format:  [[[setting.]property] [value]]
 * and return the components in 'setting', 'property' and 'value'
 * Use g_free() to deallocate the returned strings.
 */
static void
split_editor_main_cmd_args (const char *str, char **setting, char **property, char **value)
{
	char **args, **items;

	if (!str)
		return;

	args = nmc_strsplit_set (str, " \t", 2);
	if (args[0]) {
		items = nmc_strsplit_set (args[0], ".", 2);
		if (g_strv_length (items) == 2) {
			if (setting)
				*setting = g_strdup (items[0]);
			if (property)
				*property = g_strdup (items[1]);
		} else {
			if (property)
				*property = g_strdup (items[0]);
		}
		g_strfreev (items);

		if (value && args[1])
			*value = g_strstrip (g_strdup (args[1]));
	}
	g_strfreev (args);
}

static NMSetting *
is_setting_valid (NMConnection *connection, const NameItem *valid_settings, char *setting)
{
	const char *setting_name;

	if (!(setting_name = check_valid_name (setting, valid_settings, NULL)))
		return NULL;
	return nm_connection_get_setting_by_name (connection, setting_name);
}

static char *
is_property_valid (NMSetting *setting, const char *property, GError **error)
{
	char **valid_props = NULL;
	const char *prop_name;
	char *ret;

	valid_props = nmc_setting_get_valid_properties (setting);
	prop_name = nmc_string_is_valid (property, (const char **) valid_props, error);
	ret = prop_name ? g_strdup (prop_name) : NULL;
	g_strfreev (valid_props);
	return ret;
}

static NMSetting *
create_setting_by_name (const char *name, const NameItem *valid_settings)
{
	const char *setting_name;
	NMSetting *setting = NULL;

	/* Get a valid setting name */
	setting_name = check_valid_name (name, valid_settings, NULL);

	if (setting_name) {
		setting = nmc_setting_new_for_name (setting_name);
		if (!setting)
			return NULL; /* This should really not happen */
		nmc_setting_custom_init (setting);
	}
	return setting;
}

static const char *
ask_check_setting (const char *arg,
                   const NameItem *valid_settings_arr,
                   const char *valid_settings_str)
{
	char *setting_name_user;
	const char *setting_name;
	GError *err = NULL;

	if (!arg) {
		printf (_("Available settings: %s\n"), valid_settings_str);
		setting_name_user = nmc_get_user_input (EDITOR_PROMPT_SETTING);
	} else
		setting_name_user = g_strdup (arg);

	if (setting_name_user)
		g_strstrip (setting_name_user);

	if (!(setting_name = check_valid_name (setting_name_user, valid_settings_arr, &err))) {
		printf (_("Error: invalid setting name; %s\n"), err->message);
		g_clear_error (&err);
	}
	g_free (setting_name_user);
	return setting_name;
}

static const char *
ask_check_property (const char *arg,
                    const char **valid_props,
                    const char *valid_props_str)
{
	char *prop_name_user;
	const char *prop_name;
	GError *tmp_err = NULL;

	if (!arg) {
		printf (_("Available properties: %s\n"), valid_props_str);
		prop_name_user = readline_x (EDITOR_PROMPT_PROPERTY);
		if (prop_name_user)
			g_strstrip (prop_name_user);
	} else
		prop_name_user = g_strdup (arg);

	if (!(prop_name = nmc_string_is_valid (prop_name_user, valid_props, &tmp_err))) {
		printf (_("Error: property %s\n"), tmp_err->message);
		g_clear_error (&tmp_err);
	}
	g_free (prop_name_user);
	return prop_name;
}

/* Copy timestamp from src do dst */
static void
update_connection_timestamp (NMConnection *src, NMConnection *dst)
{
	NMSettingConnection *s_con_src, *s_con_dst;

	s_con_src = nm_connection_get_setting_connection (src);
	s_con_dst = nm_connection_get_setting_connection (dst);
	if (s_con_src && s_con_dst) {
		guint64 timestamp = nm_setting_connection_get_timestamp (s_con_src);
		g_object_set (s_con_dst, NM_SETTING_CONNECTION_TIMESTAMP, timestamp, NULL);
	}
}

static gboolean
confirm_connection_saving (NMConnection *local, NMConnection *remote)
{
	NMSettingConnection *s_con_loc, *s_con_rem;
	gboolean ac_local, ac_remote;
	gboolean confirmed = TRUE;

	s_con_loc = nm_connection_get_setting_connection (local);
	g_assert (s_con_loc);
	ac_local = nm_setting_connection_get_autoconnect (s_con_loc);

	if (remote) {
		s_con_rem = nm_connection_get_setting_connection (remote);
		g_assert (s_con_rem);
		ac_remote = nm_setting_connection_get_autoconnect (s_con_rem);
	} else
		ac_remote = FALSE;

	if (ac_local && !ac_remote) {
		char *answer;
		answer = nmc_get_user_input (_("Saving the connection with 'autoconnect=yes'. "
		                               "That might result in an immediate activation of the connection.\n"
		                               "Do you still want to save? [yes] "));
		if (!answer || matches (answer, "yes") == 0)
			confirmed = TRUE;
		else
			confirmed = FALSE;
		g_free (answer);
	}
	return confirmed;
}

typedef	struct {
	guint level;
	char *main_prompt;
	NMSetting *curr_setting;
	char **valid_props;
	char *valid_props_str;
} NmcEditorMenuContext;

static void
menu_switch_to_level0 (NmcEditorMenuContext *menu_ctx,
                       const char *prompt,
                       NmcTermColor prompt_color)
{
	menu_ctx->level = 0;
	g_free (menu_ctx->main_prompt);
	menu_ctx->main_prompt = nmc_colorize (prompt_color, "%s", prompt);
	menu_ctx->curr_setting = NULL;
	g_strfreev (menu_ctx->valid_props);
	menu_ctx->valid_props = NULL;
	g_free (menu_ctx->valid_props_str);
	menu_ctx->valid_props_str = NULL;
}

static void
menu_switch_to_level1 (NmcEditorMenuContext *menu_ctx,
                       NMSetting *setting,
                       const char *setting_name,
                       NmcTermColor prompt_color)
{
	menu_ctx->level = 1;
	g_free (menu_ctx->main_prompt);
	menu_ctx->main_prompt = nmc_colorize (prompt_color, "nmcli %s> ", setting_name);
	menu_ctx->curr_setting = setting;
	g_strfreev (menu_ctx->valid_props);
	menu_ctx->valid_props = nmc_setting_get_valid_properties (menu_ctx->curr_setting);
	g_free (menu_ctx->valid_props_str);
	menu_ctx->valid_props_str = g_strjoinv (", ", menu_ctx->valid_props);
}

static gboolean
editor_menu_main (NmCli *nmc, NMConnection *connection, const char *connection_type)
{
	NMRemoteConnection *rem_con = NULL;
	NmcEditorMainCmd cmd;
	char *cmd_user;
	gboolean cmd_loop = TRUE;
	char *cmd_arg = NULL;
	char *cmd_arg_s, *cmd_arg_p, *cmd_arg_v;
	const char *BASE_PROMPT = "nmcli> ";
	const NameItem *valid_settings_arr = NULL;
	char *valid_settings_str = NULL;
	AddConnectionInfo *info = NULL;
	gboolean dirty;
	GError *err1 = NULL;
	NmcEditorMenuContext menu_ctx;

	valid_settings_arr = get_valid_settings_array (connection_type);
	valid_settings_str = get_valid_options_string (valid_settings_arr);
	printf (_("You may edit the following settings: %s\n"), valid_settings_str);

	menu_ctx.level = 0;
	menu_ctx.main_prompt = nmc_colorize (nmc->editor_prompt_color, BASE_PROMPT);
	menu_ctx.curr_setting = NULL;
	menu_ctx.valid_props = NULL;
	menu_ctx.valid_props_str = NULL;

	while (cmd_loop) {
		if (!rem_con)
			rem_con = nm_remote_settings_get_connection_by_uuid (nmc->system_settings,
			                                                     nm_connection_get_uuid (connection));

		/* Connection is dirty? (not saved or differs from the saved) */
		dirty = !nm_connection_compare (connection,
		                                rem_con ? NM_CONNECTION (rem_con) : NULL,
		                                NM_SETTING_COMPARE_FLAG_EXACT);
		if (nmc->editor_status_line)
			editor_show_status_line (connection, dirty);

		cmd_user = readline_x (menu_ctx.main_prompt);
		if (!cmd_user || *cmd_user == '\0')
			continue;
		cmd = parse_editor_main_cmd (g_strstrip (cmd_user), &cmd_arg);

		cmd_arg_s = NULL;
		cmd_arg_p = NULL;
		cmd_arg_v = NULL;
		split_editor_main_cmd_args (cmd_arg, &cmd_arg_s, &cmd_arg_p, &cmd_arg_v);
		switch (cmd) {
		case NMC_EDITOR_MAIN_CMD_SET:
			/* Set property value */
			if (!cmd_arg) {
				if (menu_ctx.level == 1) {
					const char *prop_name;
					char *prop_val_user = NULL;
					char *tmp_prompt;
					const char *avals;
					GError *tmp_err = NULL;

					prop_name = ask_check_property (cmd_arg,
					                                (const char **) menu_ctx.valid_props,
					                                menu_ctx.valid_props_str);
					if (!prop_name)
						break;

					avals = nmc_setting_get_property_allowed_values (menu_ctx.curr_setting, prop_name);
					if (avals)
						printf (_("Allowed values for '%s' property: %s\n"), prop_name, avals);

					tmp_prompt = g_strdup_printf (_("Enter '%s' value: "), prop_name);
					prop_val_user = readline_x (tmp_prompt);
					g_free (tmp_prompt);

					/* Set property value */
					if (!nmc_setting_set_property (menu_ctx.curr_setting, prop_name, prop_val_user, &tmp_err)) {
						printf (_("Error: failed to set '%s' property: %s\n"), prop_name, tmp_err->message);
						g_clear_error (&tmp_err);
					}
				} else {
					printf (_("Error: no setting selected; valid are [%s]\n"), valid_settings_str);
					printf (_("use 'goto <setting>' first, or 'set <setting>.<property>'\n"));
				}
			} else {
				NMSetting *ss = NULL;
				gboolean created_ss = FALSE;
				char *prop_name;
				char *tmp_prompt;
				GError *tmp_err = NULL;

				if (cmd_arg_s) {
					/* setting provided as "setting.property" */
					ss = is_setting_valid (connection, valid_settings_arr, cmd_arg_s);
					if (!ss) {
						ss = create_setting_by_name (cmd_arg_s, valid_settings_arr);
						if (!ss) {
							printf (_("Error: invalid setting argument '%s'; valid are [%s]\n"),
							        cmd_arg_s, valid_settings_str);
							break;
						}
						created_ss = TRUE;
					}
				} else {
					if (menu_ctx.curr_setting)
						ss = menu_ctx.curr_setting;
					else {
						printf (_("Error: missing setting for '%s' property\n"), cmd_arg_p);
						break;
					}
				}

				prop_name = is_property_valid (ss, cmd_arg_p, &tmp_err);
				if (!prop_name) {
					printf (_("Error: invalid property: %s\n"), tmp_err->message);
					g_clear_error (&tmp_err);
					if (created_ss)
						g_object_unref (ss);
					break;
				}



				/* Ask for value */
				if (!cmd_arg_v) {
					const char *avals = nmc_setting_get_property_allowed_values (ss, prop_name);
					if (avals)
						printf (_("Allowed values for '%s' property: %s\n"), prop_name, avals);

					tmp_prompt = g_strdup_printf (_("Enter '%s' value: "), prop_name);
					cmd_arg_v = readline_x (tmp_prompt);
					g_free (tmp_prompt);
				}

				/* Set property value */
				if (!nmc_setting_set_property (ss, prop_name, cmd_arg_v, &tmp_err)) {
					printf (_("Error: failed to set '%s' property: %s\n"),
					        prop_name, tmp_err->message);
					g_clear_error (&tmp_err);
				}

				if (created_ss)
					nm_connection_add_setting (connection, ss);
				g_free (prop_name);
			}
			break;

		case NMC_EDITOR_MAIN_CMD_GOTO:
			/* cmd_arg_s != NULL means 'setting.property' argument */
			if (menu_ctx.level == 0 || cmd_arg_s) {
				/* in top level - no setting selected yet */
				const char *setting_name;
				NMSetting *setting;
				const char *user_arg = cmd_arg_s ? cmd_arg_s : cmd_arg_p;

				setting_name = ask_check_setting (user_arg, valid_settings_arr, valid_settings_str);
				if (!setting_name)
					break;

				setting = nm_connection_get_setting_by_name (connection, setting_name);
				if (!setting) {
					setting = nmc_setting_new_for_name (setting_name);
					if (!setting) {
						printf (_("Error: unknown setting '%s'\n"), setting_name);
						break;
					}
					nmc_setting_custom_init (setting);
					nm_connection_add_setting (connection, setting);
				}
				/* Set global variable for use in TAB completion */
				nmc_tab_completion.setting = setting;

				/* Switch to level 1 */
				menu_switch_to_level1 (&menu_ctx, setting, setting_name, nmc->editor_prompt_color);

				if (!cmd_arg_s) {
					printf (_("You may edit the following properties: %s\n"), menu_ctx.valid_props_str);
					break;
				}
			}
			if (menu_ctx.level == 1 || cmd_arg_s) {
				/* level 1 - setting selected */
				const char *prop_name;

				prop_name = ask_check_property (cmd_arg_p,
				                                (const char **) menu_ctx.valid_props,
				                                menu_ctx.valid_props_str);
				if (!prop_name)
					break;

				/* submenu - level 2 - editing properties */
				cmd_loop = property_edit_submenu (nmc, connection, rem_con, menu_ctx.curr_setting, prop_name);
			}
			break;

		case NMC_EDITOR_MAIN_CMD_REMOVE:
			/* Remove setting from connection, or delete value of a property */
			if (!cmd_arg) {
				if (menu_ctx.level == 1) {
					GError *tmp_err = NULL;
					const char *prop_name;

					prop_name = ask_check_property (cmd_arg,
					                                (const char **) menu_ctx.valid_props,
					                                menu_ctx.valid_props_str);
					if (!prop_name)
						break;

					/* Delete property value */
					if (!nmc_setting_reset_property (menu_ctx.curr_setting, prop_name, &tmp_err)) {
						printf (_("Error: failed to remove value of '%s': %s\n"), prop_name,
						        tmp_err->message);
						g_clear_error (&tmp_err);
					}
				} else
					printf (_("Error: no argument given; valid are [%s]\n"), valid_settings_str);
			} else {
				NMSetting *ss = NULL;
				gboolean descr_all;
				char *user_s;

				/* cmd_arg_s != NULL means argument is "setting.property" */
				descr_all = !cmd_arg_s && !menu_ctx.curr_setting;
				user_s = descr_all ? cmd_arg_p : cmd_arg_s ? cmd_arg_s : NULL;
				if (user_s) {
					ss = is_setting_valid (connection, valid_settings_arr, user_s);
					if (!ss) {
						if (check_valid_name (user_s, valid_settings_arr, NULL))
							printf (_("Setting '%s' is not present in the connection.\n"), user_s);
						else
							printf (_("Error: invalid setting argument '%s'; valid are [%s]\n"),
							        user_s, valid_settings_str);
						break;
					}
				} else
					ss = menu_ctx.curr_setting;

				if (descr_all) {
					/* Remove setting from the connection */
					connection_remove_setting (connection, ss);
					if (ss == menu_ctx.curr_setting) {
						/* If we removed the setting we are in, go up */
						menu_switch_to_level0 (&menu_ctx, BASE_PROMPT, nmc->editor_prompt_color);
						nmc_tab_completion.setting = NULL;  /* for TAB completion */
					}
				} else {
					GError *tmp_err = NULL;
					char *prop_name = is_property_valid (ss, cmd_arg_p, &tmp_err);
					if (prop_name) {
						/* Delete property value */
						if (!nmc_setting_reset_property (ss, prop_name, &tmp_err)) {
							printf (_("Error: failed to remove value of '%s': %s\n"), prop_name,
							        tmp_err->message);
							g_clear_error (&tmp_err);
						}
					} else {
						/* If the string is not a property, try it as a setting */
						NMSetting *s_tmp;
						s_tmp = is_setting_valid (connection, valid_settings_arr, cmd_arg_p);
						if (s_tmp) {
							/* Remove setting from the connection */
							connection_remove_setting (connection, s_tmp);
							if (ss == menu_ctx.curr_setting) {
								/* If we removed the setting we are in, go up */
								menu_switch_to_level0 (&menu_ctx, BASE_PROMPT, nmc->editor_prompt_color);
								nmc_tab_completion.setting = NULL;  /* for TAB completion */
							}
						} else
							printf (_("Error: %s properties, nor it is a setting name.\n"),
							        tmp_err->message);
						g_clear_error (&tmp_err);
					}
					g_free (prop_name);
				}
			}
			break;

		case NMC_EDITOR_MAIN_CMD_DESCRIBE:
			/* Print property description */
			if (!cmd_arg) {
				if (menu_ctx.level == 1) {
					const char *prop_name;

					prop_name = ask_check_property (cmd_arg,
					                                (const char **) menu_ctx.valid_props,
					                                menu_ctx.valid_props_str);
					if (!prop_name)
						break;

					/* Show property description */
					print_property_description (menu_ctx.curr_setting, prop_name);
				} else {
					printf (_("Error: no setting selected; valid are [%s]\n"), valid_settings_str);
					printf (_("use 'goto <setting>' first, or 'describe <setting>.<property>'\n"));
				}
			} else {
				NMSetting *ss = NULL;
				gboolean unref_ss = FALSE;
				gboolean descr_all;
				char *user_s;

				/* cmd_arg_s != NULL means argument is "setting.property" */
				descr_all = !cmd_arg_s && !menu_ctx.curr_setting;
				user_s = descr_all ? cmd_arg_p : cmd_arg_s ? cmd_arg_s : NULL;
				if (user_s) {
					ss = is_setting_valid (connection, valid_settings_arr, user_s);
					if (!ss) {
						ss = create_setting_by_name (user_s, valid_settings_arr);
						if (!ss) {
							printf (_("Error: invalid setting argument '%s'; valid are [%s]\n"),
							        user_s, valid_settings_str);
							break;
						}
						unref_ss = TRUE;
					}
				} else
					ss = menu_ctx.curr_setting;

				if (descr_all) {
					/* Show description for all properties */
					print_setting_description (ss);
				} else {
					GError *tmp_err = NULL;
					char *prop_name = is_property_valid (ss, cmd_arg_p, &tmp_err);
					if (prop_name) {
						/* Show property description */
						print_property_description (ss, prop_name);
					} else {
						/* If the string is not a property, try it as a setting */
						NMSetting *s_tmp;
						s_tmp = is_setting_valid (connection, valid_settings_arr, cmd_arg_p);
						if (s_tmp)
							print_setting_description (s_tmp);
						else
							printf (_("Error: invalid property: %s, "
							          "neither a valid setting name.\n"),
							        tmp_err->message);
						g_clear_error (&tmp_err);
					}
					g_free (prop_name);
				}
				if (unref_ss)
					g_object_unref (ss);
			}
			break;

		case NMC_EDITOR_MAIN_CMD_PRINT:
			/* Print current connection settings/properties */
			if (cmd_arg) {
				if (strcmp (cmd_arg, "all") == 0)
					editor_show_connection (connection, nmc);
				else {
					const char *s = check_valid_name (cmd_arg, valid_settings_arr, NULL);
					if (s) {
						NMSetting *ss = nm_connection_get_setting_by_name (connection, s);
						if (ss)
							editor_show_setting (ss, nmc);
						else
							printf (_("Error: '%s' setting not present\n"), s);
					}
					else
						printf (_("Error: unknown setting: '%s'\n"), cmd_arg);
				}
			} else {
				if (menu_ctx.curr_setting)
					editor_show_setting (menu_ctx.curr_setting, nmc);
				else
					editor_show_connection (connection, nmc);
			}
			break;

		case NMC_EDITOR_MAIN_CMD_VERIFY:
			/* Verify current setting or the whole connection */
			if (   menu_ctx.curr_setting
			    && (!cmd_arg || strcmp (cmd_arg, "all") != 0)) {
				GError *tmp_err = NULL;
				nm_setting_verify (menu_ctx.curr_setting, NULL, &tmp_err);
				printf (_("Verify setting '%s': %s\n"),
				        nm_setting_get_name (menu_ctx.curr_setting),
				        tmp_err ? tmp_err->message : "OK");
				g_clear_error (&tmp_err);
			} else {
				GError *tmp_err = NULL;
				nm_connection_verify (connection, &tmp_err);
				printf (_("Verify connection: %s\n"),
				        tmp_err ? tmp_err->message : "OK");
				g_clear_error (&tmp_err);
			}
			break;

		case NMC_EDITOR_MAIN_CMD_SAVE:
			/* Save the connection */
			if (nm_connection_verify (connection, &err1)) {
				/* Ask for save confirmation if the connection changes to autoconnect=yes */
				if (nmc->editor_save_confirmation)
					if (!confirm_connection_saving (connection, NM_CONNECTION (rem_con)))
						break;

				if (!rem_con) {
					/* Tell the settings service to add the new connection */
					info = g_malloc0 (sizeof (AddConnectionInfo));
					info->nmc = nmc;
					info->con_name = g_strdup (nm_connection_get_id (connection));
					nm_remote_settings_add_connection (nmc->system_settings,
					                                   connection,
					                                   add_connection_editor_cb,
					                                   info);
				} else {
					/* Save/update already saved (existing) connection */
					nm_connection_replace_settings_from_connection (NM_CONNECTION (rem_con),
					                                                connection,
					                                                NULL);
					nm_remote_connection_commit_changes (rem_con,
					                                     update_connection_editor_cb,
					                                     NULL);
				}

				g_mutex_lock (&nmc_editor_mutex);
				//FIXME: add also a timeout for cases the callback is not called
				while (!nmc_editor_cb_called)
					g_cond_wait (&nmc_editor_cond, &nmc_editor_mutex);

				if (nmc_editor_error) {
					printf (_("Error: Failed to save '%s' (%s) connection: (%d) %s\n"),
					        nm_connection_get_id (connection),
					        nm_connection_get_uuid (connection),
					        nmc_editor_error->code, nmc_editor_error->message);

					g_error_free (nmc_editor_error);
				} else {
					NMRemoteConnection *con_tmp;

					printf (_("Connection '%s' (%s) successfully saved.\n"),
					        nm_connection_get_id (connection),
					        nm_connection_get_uuid (connection));

					/* Replace local connection with the remote one to be sure they are equal.
					 * This mitigates problems with plugins not preserving some properties or
					 * adding ipv{4,6} settings when not present.
					 */
					con_tmp = nm_remote_settings_get_connection_by_uuid (nmc->system_settings,
					                                                     nm_connection_get_uuid (connection));
					if (con_tmp)
						nm_connection_replace_settings_from_connection (connection,
						                                                NM_CONNECTION (con_tmp),
						                                                NULL);
				}

				nmc_editor_cb_called = FALSE;
				nmc_editor_error = NULL;
				g_mutex_unlock (&nmc_editor_mutex);
			} else
				printf (_("Error: connection verification failed: %s\n"),
				        err1 ? err1->message : _("(unknown error)"));

			g_clear_error (&err1);
			break;

		case NMC_EDITOR_MAIN_CMD_ACTIVATE:
			{
			GError *tmp_err = NULL;
			const char *ifname = cmd_arg_p;
			const char *ap_nsp = cmd_arg_v;

			/* When only AP/NSP is specified it is prepended with '/' */
			if (!cmd_arg_v) {
				if (ifname && ifname[0] == '/') {
					ap_nsp = ifname + 1;
					ifname = NULL;
				}
			} else
				ap_nsp = ap_nsp && ap_nsp[0] == '/' ? ap_nsp + 1 : ap_nsp;

			if (dirty) {
				printf (_("Error: connection is not saved. Type 'save' first.\n"));
				break;
			}
			if (!nm_connection_verify (NM_CONNECTION (rem_con), &tmp_err)) {
				printf (_("Error: connection is not valid: %s\n"), tmp_err->message);
				g_clear_error (&tmp_err);
				break;
			}
			nmc->get_client (nmc);

			nmc->nowait_flag = FALSE;
			nmc->should_wait = TRUE;
			nmc->print_output = NMC_PRINT_PRETTY;
			if (!nmc_activate_connection (nmc, NM_CONNECTION (rem_con), ifname, ap_nsp, ap_nsp,
			                              activate_connection_editor_cb, &tmp_err)) {
				printf (_("Error: Cannot activate connection: %s.\n"), tmp_err->message);
				g_clear_error (&tmp_err);
				break;
			}

			g_mutex_lock (&nmc_editor_mutex);
			while (!nmc_editor_cb_called)
				g_cond_wait (&nmc_editor_cond, &nmc_editor_mutex);

			if (nmc_editor_error) {
				printf (_("Error: Failed to activate '%s' (%s) connection: (%d) %s\n"),
				        nm_connection_get_id (connection),
				        nm_connection_get_uuid (connection),
				        nmc_editor_error->code, nmc_editor_error->message);
				g_error_free (nmc_editor_error);
			} else {
				printf (_("Monitoring connection activation (press any key to continue)\n"));
				nmc_get_user_input ("");
			}

			if (nmc_editor_monitor_ac) {
				if (nmc_editor_monitor_ac->monitor_id)
					g_source_remove (nmc_editor_monitor_ac->monitor_id);
				g_free (nmc_editor_monitor_ac);
			}
			nmc_editor_cb_called = FALSE;
			nmc_editor_error = NULL;
			nmc_editor_monitor_ac = NULL;
			g_mutex_unlock (&nmc_editor_mutex);

			/* Update timestamp in local connection */
			update_connection_timestamp (NM_CONNECTION (rem_con), connection);

			}
			break;

		case NMC_EDITOR_MAIN_CMD_BACK:
			/* Go back (up) an the menu */
			if (menu_ctx.level == 1) {
				menu_switch_to_level0 (&menu_ctx, BASE_PROMPT, nmc->editor_prompt_color);
				nmc_tab_completion.setting = NULL;  /* for TAB completion */
			}
			break;

		case NMC_EDITOR_MAIN_CMD_HELP:
			/* Print command help */
			editor_main_help (cmd_arg);
			break;

		case NMC_EDITOR_MAIN_CMD_NMCLI:
			if (cmd_arg_p && matches (cmd_arg_p, "status-line") == 0) {
				GError *tmp_err = NULL;
				gboolean bb;
				if (!nmc_string_to_bool (cmd_arg_v ? g_strstrip (cmd_arg_v) : "", &bb, &tmp_err)) {
					printf (_("Error: status-line: %s\n"), tmp_err->message);
					g_clear_error (&tmp_err);
				} else
					nmc->editor_status_line = bb;
			} else if (cmd_arg_p && matches (cmd_arg_p, "save-confirmation") == 0) {
				GError *tmp_err = NULL;
				gboolean bb;
				if (!nmc_string_to_bool (cmd_arg_v ? g_strstrip (cmd_arg_v) : "", &bb, &tmp_err)) {
					printf (_("Error: save-confirmation: %s\n"), tmp_err->message);
					g_clear_error (&tmp_err);
				} else
					nmc->editor_save_confirmation = bb;
			} else if (cmd_arg_p && matches (cmd_arg_p, "prompt-color") == 0) {
				unsigned long color;
				if (!nmc_string_to_uint (cmd_arg_v ? g_strstrip (cmd_arg_v) : "X",
				                         TRUE, 0, 8, &color))
					printf (_("Error: bad color number: '%s'; use <0-8>\n"),
					        cmd_arg_v ? cmd_arg_v : "");
				else {
					nmc->editor_prompt_color = color;
					g_free (menu_ctx.main_prompt);
					if (menu_ctx.level == 0)
						menu_ctx.main_prompt = nmc_colorize (nmc->editor_prompt_color, BASE_PROMPT);
					else
						menu_ctx.main_prompt = nmc_colorize (nmc->editor_prompt_color, "nmcli %s> ",
						                                     nm_setting_get_name (menu_ctx.curr_setting));
				}
			} else if (!cmd_arg_p) {
				printf (_("Current nmcli configuration:\n"));
				printf ("status-line: %s\n"
				        "save-confirmation: %s\n"
				        "prompt-color: %d\n",
				        nmc->editor_status_line ? "yes" : "no",
				        nmc->editor_save_confirmation ? "yes" : "no",
				        nmc->editor_prompt_color);
			} else
				printf (_("Invalid configuration option '%s'; allowed [%s]\n"),
				        cmd_arg_v ? cmd_arg_v : "", "status-line, save-confirmation, prompt-color");

			break;

		case NMC_EDITOR_MAIN_CMD_QUIT:
			if (dirty) {
				char *tmp_str;
				do {
					tmp_str = nmc_get_user_input (_("The connection is not saved. "
					                                "Do you really want to quit? [y/n]\n"));
				} while (!tmp_str);
				if (matches (tmp_str, "yes") == 0)
					cmd_loop = FALSE;  /* quit command loop */
				g_free (tmp_str);
			} else
				cmd_loop = FALSE;  /* quit command loop */
			break;

		case NMC_EDITOR_MAIN_CMD_UNKNOWN:
		default:
			printf (_("Unknown command: '%s'\n"), cmd_user);
			break;
		}

		g_free (cmd_user);
		g_free (cmd_arg);
		g_free (cmd_arg_s);
		g_free (cmd_arg_p);
		g_free (cmd_arg_v);
	}
	g_free (valid_settings_str);
	g_free (menu_ctx.main_prompt);
	g_strfreev (menu_ctx.valid_props);
	g_free (menu_ctx.valid_props_str);

	/* Save history file */
	save_history_cmds (nm_connection_get_uuid (connection));

	return TRUE;
}

static const char *
get_ethernet_device_name (NmCli *nmc)
{
	const GPtrArray *devices;
	int i;

	nmc->get_client (nmc);
	devices = nm_client_get_devices (nmc->client);
	for (i = 0; devices && (i < devices->len); i++) {
		NMDevice *dev = g_ptr_array_index (devices, i);
		if (NM_IS_DEVICE_ETHERNET (dev))
			return nm_device_get_iface (dev);
	}
	return NULL;
}

static void
editor_init_new_connection (NmCli *nmc, NMConnection *connection)
{
	NMSetting *setting, *base_setting;
	NMSettingConnection *s_con;
	const char *con_type;
	const char *slave_type = NULL;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	con_type = nm_setting_connection_get_connection_type (s_con);

	/* Initialize new connection according to its type using sensible defaults. */

	if (g_strcmp0 (con_type, "bond-slave") == 0)
		slave_type = NM_SETTING_BOND_SETTING_NAME;
	if (g_strcmp0 (con_type, "team-slave") == 0)
		slave_type = NM_SETTING_TEAM_SETTING_NAME;
	if (g_strcmp0 (con_type, "bridge-slave") == 0)
		slave_type = NM_SETTING_BRIDGE_SETTING_NAME;

	if (slave_type) {
		const char *dev_ifname = get_ethernet_device_name (nmc);

		/* For bond/team/bridge slaves add 'wired' setting */
		setting = nm_setting_wired_new ();
		nm_connection_add_setting (connection, setting);

		g_object_set (s_con,
		              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
		              NM_SETTING_CONNECTION_MASTER, dev_ifname ? dev_ifname : "eth0",
		              NM_SETTING_CONNECTION_SLAVE_TYPE, slave_type,
		              NULL);
	} else {
		/* Add a "base" setting to the connection by default */
		base_setting = nmc_setting_new_for_name (con_type);
		if (!base_setting)
			return;
		nm_connection_add_setting (connection, base_setting);

		/* Set a sensible bond/bridge interface name by default */
		if (g_strcmp0 (con_type, NM_SETTING_BOND_SETTING_NAME) == 0)
			g_object_set (NM_SETTING_BOND (base_setting),
			              NM_SETTING_BOND_INTERFACE_NAME, "nm-bond",
			              NULL);
		if (g_strcmp0 (con_type, NM_SETTING_BRIDGE_SETTING_NAME) == 0)
			g_object_set (NM_SETTING_BRIDGE (base_setting),
			              NM_SETTING_BRIDGE_INTERFACE_NAME, "nm-bridge",
			              NULL);

		/* Set sensible initial VLAN values */
		if (g_strcmp0 (con_type, NM_SETTING_VLAN_SETTING_NAME) == 0) {
			const char *dev_ifname = get_ethernet_device_name (nmc);

			g_object_set (NM_SETTING_VLAN (base_setting),
			              NM_SETTING_VLAN_PARENT, dev_ifname ? dev_ifname : "eth0",
			              NM_SETTING_VLAN_ID, 1,
			              NULL);
			g_object_set (s_con,
			              NM_SETTING_CONNECTION_MASTER, dev_ifname ? dev_ifname : "eth0",
			              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_VLAN_SETTING_NAME,
			              NULL);
		}

		/* Initialize 'transport-mode' so that 'infiniband' is valid */
		if (g_strcmp0 (con_type, NM_SETTING_INFINIBAND_SETTING_NAME) == 0)
			g_object_set (NM_SETTING_INFINIBAND (base_setting),
			              NM_SETTING_INFINIBAND_TRANSPORT_MODE, "datagram",
			              NULL);

		/* Initialize 'number' so that 'cdma' is valid */
		if (g_strcmp0 (con_type, NM_SETTING_CDMA_SETTING_NAME) == 0)
			g_object_set (NM_SETTING_CDMA (base_setting),
			              NM_SETTING_CDMA_NUMBER, "#777",
			              NULL);

		/* Initialize 'number' so that 'gsm' is valid */
		if (g_strcmp0 (con_type, NM_SETTING_GSM_SETTING_NAME) == 0)
			g_object_set (NM_SETTING_GSM (base_setting),
			              NM_SETTING_GSM_NUMBER, "*99#",
			              NULL);

		/* For Wi-Fi set mode to "infrastructure". Even though mode == NULL
		 * is regarded as "infrastructure", explicit value makes no doubts.
		 */
		if (g_strcmp0 (con_type, NM_SETTING_WIRELESS_SETTING_NAME) == 0)
			g_object_set (NM_SETTING_WIRELESS (base_setting),
			              NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_INFRA,
			              NULL);

		/* Always add IPv4 and IPv6 settings for non-slave connections */
		setting = nm_setting_ip4_config_new ();
		nmc_setting_custom_init (setting);
		nm_connection_add_setting (connection, setting);

		setting = nm_setting_ip6_config_new ();
		nmc_setting_custom_init (setting);
		nm_connection_add_setting (connection, setting);
	}
}

static void
editor_init_existing_connection (NMConnection *connection)
{
	NMSettingIP4Config *s_ip4;
	NMSettingIP6Config *s_ip6;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	s_ip6 = nm_connection_get_setting_ip6_config (connection);

	if (s_ip4)
		nmc_setting_ip4_connect_handlers (s_ip4);
	if (s_ip6)
		nmc_setting_ip6_connect_handlers (s_ip6);
}

static NMCResultCode
do_connection_edit (NmCli *nmc, int argc, char **argv)
{
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	const char *connection_type;
	char *uuid;
	char *default_name = NULL;
	const char *type = NULL;
	char *type_ask = NULL;
	const char *con_name = NULL;
	const char *con = NULL;
	const char *con_id = NULL;
	const char *con_uuid = NULL;
	const char *con_path = NULL;
	const char *selector = NULL;
	char *tmp_str;
	GError *error = NULL;
	GError *err1 = NULL;
	GModule *edit_lib_module = NULL;
	nmc_arg_t exp_args[] = { {"type",     TRUE, &type,     FALSE},
	                         {"con-name", TRUE, &con_name, FALSE},
	                         {"id",       TRUE, &con_id,   FALSE},
	                         {"uuid",     TRUE, &con_uuid, FALSE},
	                         {"path",     TRUE, &con_path, FALSE},
	                         {NULL} };

	nmc->return_value = NMC_RESULT_SUCCESS;

	if (argc == 1)
		con = *argv;
	else {
		if (!nmc_parse_args (exp_args, TRUE, &argc, &argv, &error)) {
			g_string_assign (nmc->return_text, error->message);
			nmc->return_value = error->code;
			g_clear_error (&error);
			goto error;
		}
	}

	/* Load line editing library */
	if (!(edit_lib_module = load_cmd_line_edit_lib ())) {
		printf (_(">>> Command-line editing is not available. "
		          "Consider installing a line editing library to enable the feature. <<<\n"
		          "Supported libraries are:\n"
		          "  - GNU Readline    (libreadline) http://cnswww.cns.cwru.edu/php/chet/readline/rltop.html\n"
		          "  - NetBSD Editline (libedit)     http://www.thrysoee.dk/editline/\n"));
		edit_lib_symbols.readline_func = NULL;
		edit_lib_symbols.add_history_func = NULL;
		edit_lib_symbols.history_list_func = NULL;
		edit_lib_symbols.rl_insert_text_func = NULL;
		edit_lib_symbols.rl_startup_hook_x = NULL;
	}

	if (!con) {
		if (con_id && !con_uuid && !con_path) {
			con = con_id;
			selector = "id";
		} else if (con_uuid && !con_id && !con_path) {
			con = con_uuid;
			selector = "uuid";
		} else if (con_path && !con_id && !con_uuid) {
			con = con_path;
			selector = "path";
		} else if (!con_path && !con_id && !con_uuid) {
			/* no-op */
		} else {
			g_string_printf (nmc->return_text,
			                 _("Error: only one of 'id', uuid, or 'path' can be provided."));
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto error;
		}
	}

	if (con) {
		/* Existing connection */
		NMConnection *found_con;

		found_con = find_connection (nmc->system_connections, selector, con);
		if (!found_con) {
			g_string_printf (nmc->return_text, _("Error: Unknown connection '%s'."), con);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto error;
		}

		/* Duplicate the connection and use that so that we need not
		 * differentiate existing vs. new later
		 */
		connection = nm_connection_duplicate (found_con);

		s_con = nm_connection_get_setting_connection (connection);
		g_assert (s_con);
		connection_type = nm_setting_connection_get_connection_type (s_con);

		if (type)
			printf (_("Warning: editing existing connection '%s'; 'type' argument is ignored\n"),
			        nm_connection_get_id (connection));
		if (con_name)
			printf (_("Warning: editing existing connection '%s'; 'con-name' argument is ignored\n"),
			        nm_connection_get_id (connection));

		/* Load previously saved history commands for the connection */
		load_history_cmds (nm_connection_get_uuid (connection));

		editor_init_existing_connection (connection);
	} else {
		/* New connection */
		connection_type = check_valid_name (type, nmc_valid_connection_types, &err1);
		tmp_str = get_valid_options_string (nmc_valid_connection_types);

		while (!connection_type) {
			if (!type)
				printf (_("Valid connection types: %s\n"), tmp_str);
			else
				printf (_("Error: invalid connection type; %s\n"), err1->message);
			g_clear_error (&err1);

			type_ask = readline_x (EDITOR_PROMPT_CON_TYPE);
			type = type_ask = type_ask ? g_strstrip (type_ask) : NULL;
			connection_type = check_valid_name (type_ask, nmc_valid_connection_types, &err1);
			g_free (type_ask);
		}
		g_free (tmp_str);

		/* Create a new connection object */
		connection = nm_connection_new ();

		/* Build up the 'connection' setting */
		s_con = (NMSettingConnection *) nm_setting_connection_new ();
		uuid = nm_utils_uuid_generate ();
		if (con_name)
			default_name = g_strdup (con_name);
		else
			default_name = unique_connection_name (nmc->system_connections,
			                                       get_name_alias (connection_type, nmc_valid_connection_types));

		g_object_set (s_con,
		              NM_SETTING_CONNECTION_ID, default_name,
		              NM_SETTING_CONNECTION_UUID, uuid,
		              NM_SETTING_CONNECTION_TYPE, connection_type,
		              NULL);
		g_free (uuid);
		g_free (default_name);
		nm_connection_add_setting (connection, NM_SETTING (s_con));

		/* Initialize the new connection so that it is valid from the start */
		editor_init_new_connection (nmc, connection);
	}

	printf ("\n");
	printf (_("===| nmcli interactive connection editor |==="));
	printf ("\n\n");
	if (con)
		printf (_("Editing existing '%s' connection: '%s'"), connection_type, con);
	else
		printf (_("Adding a new '%s' connection"), connection_type);
	printf ("\n\n");
	printf (_("Type 'help' or '?' for available commands."));
	printf ("\n");
	printf (_("Type 'describe [<setting>.<prop>]' for detailed property description."));
	printf ("\n\n");

	/* Set global variables for use in TAB completion */
	nmc_tab_completion.nmc = nmc;
	nmc_tab_completion.con_type = connection_type;
	nmc_tab_completion.connection = connection;

	/* Run menu loop */
	editor_menu_main (nmc, connection, connection_type);

	if (edit_lib_module)
		g_module_close (edit_lib_module);

	if (connection)
		g_object_unref (connection);

	nmc->should_wait = TRUE;
	return nmc->return_value;

error:
	if (connection)
		g_object_unref (connection);
	g_free (type_ask);

	nmc->should_wait = FALSE;
	return nmc->return_value;
}


static void
modify_connection_cb (NMRemoteConnection *connection,
                      GError *error,
                      gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;

        if (error) {
		g_string_printf (nmc->return_text,
		                 _("Error: Failed to modify connection '%s': (%d) %s"),
		                 nm_connection_get_id (NM_CONNECTION (connection)),
		                 error->code, error->message);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
	} else {
		if (nmc->print_output == NMC_PRINT_PRETTY)
			printf (_("Connection '%s' (%s) successfully modified.\n"),
		                nm_connection_get_id (NM_CONNECTION (connection)),
		                nm_connection_get_uuid (NM_CONNECTION (connection)));
	}
	quit ();
}

static NMCResultCode
do_connection_modify (NmCli *nmc, int argc, char **argv)
{
	NMConnection *connection = NULL;
	NMRemoteConnection *rc = NULL;
	NMSetting *setting;
	NMSettingConnection *s_con;
	const char *con_type;
	const char *name;
	const char *selector = NULL;
	const char *set_prop;
	char *value = NULL;
	char **strv = NULL;
	const char *setting_name;
	char *property_name = NULL;
	GError *error = NULL;

	nmc->should_wait = FALSE;

	if (argc == 0) {
		g_string_printf (nmc->return_text, _("Error: No arguments provided."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}
	if (   strcmp (*argv, "id") == 0
	    || strcmp (*argv, "uuid") == 0
	    || strcmp (*argv, "path") == 0) {

		selector = *argv;
		if (next_arg (&argc, &argv) != 0) {
			g_string_printf (nmc->return_text, _("Error: %s argument is missing."),
			                 selector);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto finish;
		}
		name = *argv;
	}
	name = *argv;
	next_arg (&argc, &argv);
	set_prop = *argv;
	next_arg (&argc, &argv);
	value = g_strjoinv (" ", argv);

	if (!name) {
		g_string_printf (nmc->return_text, _("Error: connection ID is missing."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}
	if (!set_prop) {
		g_string_printf (nmc->return_text, _("Error: <setting>.<property> argument is missing."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}
	/* NULL value means deleting/setting default property value */

	/* create NMClient */
	nmc->get_client (nmc);

	if (!nm_client_get_manager_running (nmc->client)) {
		g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
		nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		goto finish;
	}

	connection = find_connection (nmc->system_connections, selector, name);
	if (!connection) {
		g_string_printf (nmc->return_text, _("Error: Unknown connection '%s'."), name);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}
	strv = g_strsplit (set_prop, ".", 2);
	if (g_strv_length (strv) != 2) {
		g_string_printf (nmc->return_text, _("Error: invalid <setting>.<property> '%s'."),
		                 set_prop);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}

	rc = nm_remote_settings_get_connection_by_uuid (nmc->system_settings,
	                                                nm_connection_get_uuid (connection));

	s_con = nm_connection_get_setting_connection (NM_CONNECTION (rc));
	g_assert (s_con);
	con_type = nm_setting_connection_get_connection_type (s_con);

	setting_name = check_valid_name (strv[0], get_valid_settings_array (con_type), &error);
	if (!setting_name) {
		g_string_printf (nmc->return_text, _("Error: invalid or not allowed setting '%s': %s."),
		                 strv[0], error->message);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}
	setting = nm_connection_get_setting_by_name (NM_CONNECTION (rc), setting_name);
	if (!setting) {
		setting = nmc_setting_new_for_name (setting_name);
		if (!setting) {
			/* This should really not happen */
			g_string_printf (nmc->return_text,
			                 "Error: don't know how to create '%s' setting.",
			                 setting_name);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			goto finish;
		}
		nm_connection_add_setting (NM_CONNECTION (rc), setting);
	}

	property_name = is_property_valid (setting, strv[1], &error);
	if (!property_name) {
		g_string_printf (nmc->return_text, _("Error: invalid property '%s': %s."),
		                 strv[1], error->message);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}
	if (!nmc_setting_set_property (setting, property_name, value, &error)) {
		g_string_printf (nmc->return_text, _("Error: failed to modify %s.%s: %s."),
		                 strv[0], strv[1], error->message);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}

	nm_remote_connection_commit_changes (rc,
	                                     modify_connection_cb,
	                                     nmc);
finish:
	nmc->should_wait = (nmc->return_value == NMC_RESULT_SUCCESS);
	g_free (value);
	g_free (property_name);
	g_strfreev (strv);
	g_clear_error (&error);
	return nmc->return_value;
}


typedef struct {
	NmCli *nmc;
	int counter;
} DeleteStateInfo;

static void
delete_cb (NMRemoteConnection *con, GError *err, gpointer user_data)
{
	DeleteStateInfo *info = (DeleteStateInfo *) user_data;

	if (err) {
		g_string_printf (info->nmc->return_text, _("Error: Connection deletion failed: %s"), err->message);
		info->nmc->return_value = NMC_RESULT_ERROR_CON_DEL;
	}

	info->counter--;
	if (info->counter == 0) {
		g_free (info);
		quit ();
	}
}

static NMCResultCode
do_connection_delete (NmCli *nmc, int argc, char **argv)
{
	NMConnection *connection = NULL;
	DeleteStateInfo *del_info = NULL;
	char *line = NULL;
	char **arg_arr = NULL;
	char **arg_ptr = argv;
	int arg_num = argc;
	GString *invalid_cons = NULL;
	gboolean del_info_free = FALSE;

	nmc->return_value = NMC_RESULT_SUCCESS;
	nmc->should_wait = FALSE;

	/* create NMClient */
	nmc->get_client (nmc);

	if (!nm_client_get_manager_running (nmc->client)) {
		g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
		nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		goto finish;
	}

	if (argc == 0) {
		if (nmc->ask) {
			line = nmc_get_user_input (_("Connection (name, UUID, or path): "));
			nmc_string_to_arg_array (line, "", &arg_arr, &arg_num);
			arg_ptr = arg_arr;
		}
		if (arg_num == 0) {
			g_string_printf (nmc->return_text, _("Error: No connection specified."));
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto finish;
		}
	}

	del_info = g_malloc0 (sizeof (DeleteStateInfo));
	del_info->nmc = nmc;
	del_info->counter = 0;
	del_info_free = TRUE;

	while (arg_num > 0) {
		const char *selector = NULL;

		if (   strcmp (*arg_ptr, "id") == 0
		    || strcmp (*arg_ptr, "uuid") == 0
		    || strcmp (*arg_ptr, "path") == 0) {
			selector = *arg_ptr;
			if (next_arg (&arg_num, &arg_ptr) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), selector);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
		}

		connection = find_connection (nmc->system_connections, selector, *arg_ptr);
		if (!connection) {
			if (nmc->print_output != NMC_PRINT_TERSE)
				printf (_("Error: unknown connection: %s\n"), *arg_ptr);

			if (!invalid_cons)
				invalid_cons = g_string_new (NULL);
			g_string_append_printf (invalid_cons, "'%s', ", *arg_ptr);

			/* take the next argument and continue */
			next_arg (&arg_num, &arg_ptr);
			continue;
		}

		/* We need to wait a bit so that nmcli's permissions can be checked.
		 * We will exit when D-Bus return (error) messages are received.
		 */
		nmc->should_wait = TRUE;

		/* del_info deallocation is handled in delete_cb() */
		del_info_free = FALSE;

		del_info->counter++;

		/* Delete the connection */
		nm_remote_connection_delete (NM_REMOTE_CONNECTION (connection), delete_cb, del_info);

		next_arg (&arg_num, &arg_ptr);
	}

finish:
	if (del_info_free)
		g_free (del_info);
	g_strfreev (arg_arr);

	if (invalid_cons) {
		g_string_truncate (invalid_cons, invalid_cons->len-2);  /* truncate trailing ", " */
		g_string_printf (nmc->return_text, _("Error: cannot delete unknown connection(s): %s."),
		                 invalid_cons->str);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		g_string_free (invalid_cons, TRUE);
	}
	return nmc->return_value;
}

static NMCResultCode
do_connection_reload (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;

	nmc->return_value = NMC_RESULT_SUCCESS;
	nmc->should_wait = FALSE;

	if (!nm_client_get_manager_running (nmc->client)) {
		g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
		nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		return nmc->return_value;
	}

	if (!nm_remote_settings_reload_connections (nmc->system_settings, &error)) {
		g_string_printf (nmc->return_text, _("Error: %s."), error->message);
		if (error->code == NM_REMOTE_SETTINGS_ERROR_SERVICE_UNAVAILABLE)
			nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		else
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		g_clear_error (&error);
	}

	return nmc->return_value;
}


typedef struct {
	NmCli *nmc;
	int argc;
	char **argv;
} NmcEditorThreadData;

static GThread *editor_thread;
static NmcEditorThreadData editor_thread_data;

/*
 * We need to run do_connection_edit() in a thread so that
 * glib main loop is not blocked and could receive and process D-Bus
 * return messages.
 */
static gpointer
connection_editor_thread_func (gpointer data)
{
	NmcEditorThreadData *td = (NmcEditorThreadData *) data;

	/* run editor for editing/adding connections */
	td->nmc->return_value = do_connection_edit (td->nmc, td->argc, td->argv);

	/* quit glib main loop now that we are done with this thread */
	quit ();

	return NULL;
}

static NMCResultCode
parse_cmd (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;
	int arg_ret;

	if (argc == 0) {
		if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
			goto opt_error;
		nmc->return_value = do_connections_show (nmc, argc, argv);
	} else {
		if (nmc_arg_is_help (*argv)) {
			usage ();
			nmc->should_wait = FALSE;
		}
		else if (matches (*argv, "show") == 0) {
			arg_ret = next_arg (&argc, &argv);
			if (arg_ret != 0 || matches (*argv, "configured") == 0) {
				next_arg (&argc, &argv);
				nmc->return_value = do_connections_show (nmc, argc, argv);
			} else if (matches (*argv, "active") == 0) {
				if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
					goto opt_error;
				nmc->return_value = do_connections_show_active (nmc, argc-1, argv+1);
			} else {
				g_string_printf (nmc->return_text, _("Error: 'configured' or 'active' command is expected for 'connection show'."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				nmc->should_wait = FALSE;
			}
		}
		else if (matches(*argv, "up") == 0) {
			nmc->return_value = do_connection_up (nmc, argc-1, argv+1);
		}
		else if (matches(*argv, "down") == 0) {
			nmc->return_value = do_connection_down (nmc, argc-1, argv+1);
		}
		else if (matches(*argv, "add") == 0) {
			if (nmc_arg_is_help (*(argv+1))) {
				usage_connection_add ();
				nmc->should_wait = FALSE;
			} else
				nmc->return_value = do_connection_add (nmc, argc-1, argv+1);
		}
		else if (matches(*argv, "edit") == 0) {
			editor_thread_data.nmc = nmc;
			editor_thread_data.argc = argc - 1;
			editor_thread_data.argv = argv + 1;
			editor_thread = g_thread_new ("editor-thread", connection_editor_thread_func, &editor_thread_data);
			g_thread_unref (editor_thread);
		}
		else if (matches(*argv, "delete") == 0) {
			nmc->return_value = do_connection_delete (nmc, argc-1, argv+1);
		}
		else if (matches(*argv, "reload") == 0) {
			nmc->return_value = do_connection_reload (nmc, argc-1, argv+1);
		}
		else if (matches (*argv, "modify") == 0) {
			nmc->return_value = do_connection_modify (nmc, argc-1, argv+1);
		}
		else {
			usage ();
			g_string_printf (nmc->return_text, _("Error: '%s' is not valid 'connection' command."), *argv);
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

/* Entry point function for connections-related commands: 'nmcli connection' */
NMCResultCode
do_connections (NmCli *nmc, int argc, char **argv)
{
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

		/* Get NMClient object early */
		nmc->get_client (nmc);

		nmc->should_wait = TRUE;

		args_info.nmc = nmc;
		args_info.argc = argc;
		args_info.argv = argv;

		/* get system settings */
		if (!(nmc->system_settings = nm_remote_settings_new (NULL))) {
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

		/* The rest will be done in get_connection_cb() callback.
		 * We need to wait for signals that connections are read.
		 */
		return NMC_RESULT_SUCCESS;
	}
}
