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
#include <nm-device-bridge.h>
#include <nm-device-vlan.h>
#include <nm-remote-settings.h>
#include <nm-vpn-connection.h>
#include <nm-utils.h>

#include "utils.h"
#include "common.h"
#include "settings.h"
#include "connections.h"

/* Activation timeout waiting for bond/bridge slaves (in seconds) */
#define BB_SLAVES_TIMEOUT 10

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
                                         NM_SETTING_BRIDGE_PORT_SETTING_NAME
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

static void
usage (void)
{
	fprintf (stderr,
	         _("Usage: nmcli connection { COMMAND | help }\n"
	         "  COMMAND := { show | up | down | delete }\n\n"
	         "  show configured [[ id | uuid | path ] <ID>]\n\n"
	         "  show active     [[ id | uuid | path | apath ] <ID>]\n\n"
#if WITH_WIMAX
	         "  up [ id | uuid | path ] <ID> [ifname <ifname>] [ap <BSSID>] [nsp <name>]\n\n"
#else
	         "  up [ id | uuid | path ] <ID> [ifname <ifname>] [ap <BSSID>]\n\n"
#endif
	         "  down [ id | uuid | path | apath ] <ID>\n\n"
	         "  add COMMON_OPTIONS TYPE_SPECIFIC_OPTIONS IP_OPTIONS\n\n"
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
	         "    wifi:         [mac <MAC address>]\n"
	         "                  [cloned-mac <cloned MAC address>]\n"
	         "                  [mtu <MTU>]\n"
	         "                  [ssid <SSID>]\n\n"
	         "    wimax:        [mac <MAC address>]\n"
	         "                  [nsp <NSP>]\n\n"
	         "    gsm:          apn <APN>]\n"
	         "                  [user <username>]\n"
	         "                  [password <password>]\n\n"
	         "    cdma:         [user <username>]\n"
	         "                  [password <password>]\n\n"
	         "    infiniband:   [mac <MAC address>]\n"
	         "                  [mtu <MTU>]\n"
	         "                  [transport-mode datagram | connected]\n\n"
	         "                  [parent <ifname>]\n\n"
	         "                  [p-key <IPoIB P_Key>]\n\n"
	         "    bluetooth:    [addr <bluetooth address>]\n"
	         "                  [bt-type panu|dun-gsm|dun-cdma]\n"
	         "    vlan:         dev <parent device (connection  UUID, ifname, or MAC)\n"
	         "                  [id <VLAN id>]\n"
	         "                  [flags <VLAN flags>]\n"
	         "                  [ingress <ingress priority mapping>]\n"
	         "                  [egress <egress priority mapping>]\n"
	         "                  [mtu <MTU>]\n\n"
	         "    bond:         [mode balance-rr (0) | active-backup (1) | balance-xor (2) | broadcast (3) |\n"
	         "                        802.3ad    (4) | balance-tlb   (5) | balance-alb (6)]\n"
	         "                  [miimon <num>]\n"
	         "                  [downdelay <num>]\n"
	         "                  [updelay <num>]\n"
	         "                  [arp_interval <num>]\n"
	         "                  [arp_ip_traget <num>]\n\n"
	         "    bond-slave:   master <master (ifname or connection UUID)\n\n"
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
		g_array_free (print_settings_array, FALSE);

	return TRUE;
}

static void
fill_output_connection (NMConnection *data, gpointer user_data)
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
		        && (strcmp (filter_val, path) == 0 || (filter_type && g_strcmp0 (filter_val, path_num) == 0))))
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
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;
	gboolean printed = FALSE;

	nmc->should_wait = FALSE;

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else
		fields_str = nmc->required_fields;

	tmpl = nmc_fields_con_show;
	tmpl_len = sizeof (nmc_fields_con_show);
	nmc->print_fields.indices = parse_output_fields (fields_str, tmpl, &error1);
	/* error1 is checked later - it's not valid for connection details */

	if (argc == 0) {
		if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error2))
			goto error;
		if (error1)
			goto error;

		/* Add headers */
		nmc->print_fields.header_name = _("List of configured connections");
		arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
		g_ptr_array_add (nmc->output_data, arr);

		/* Add values */
		g_slist_foreach (nmc->system_connections, (GFunc) fill_output_connection, nmc);
		print_data (nmc);  /* Print all data */
	} else {
		g_clear_error (&error1); /* the error1 is only relevant for 'show configured' without arguments */

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
		        && (strcmp (filter_val, path) == 0 || (filter_type && g_strcmp0 (filter_val, path_num) == 0)))
		    || (   (!filter_type || strcmp (filter_type, "apath") == 0)
		        && (strcmp (filter_val, a_path) == 0 || (filter_type && g_strcmp0 (filter_val, a_path_num) == 0))))
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
		g_array_free (print_groups, FALSE);

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
		if (nmc->print_output == NMC_PRINT_PRETTY) {
			nmc_terminal_erase_line ();
			printf (_("Connection successfully activated (D-Bus active path: %s)\n"),
			        nm_object_get_path (NM_OBJECT (active)));
		}
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
		/* no operation */
		break;

	case NM_VPN_CONNECTION_STATE_ACTIVATED:
		if (nmc->print_output == NMC_PRINT_PRETTY) {
			nmc_terminal_erase_line ();
			printf (_("VPN connection successfully activated (D-Bus active path: %s)\n"),
			        nm_object_get_path (NM_OBJECT (vpn)));
		}
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
	const char *con_type;
} ActivateConnectionInfo;

static gboolean
bond_bridge_slaves_check (gpointer user_data)
{
	ActivateConnectionInfo *info = (ActivateConnectionInfo *) user_data;
	NmCli *nmc = info->nmc;
	NMDevice *device = info->device;
	const char *con_type = info->con_type;
	const GPtrArray *slaves = NULL;

	if (strcmp (con_type, NM_SETTING_BOND_SETTING_NAME) == 0)
		slaves = nm_device_bond_get_slaves (NM_DEVICE_BOND (device));
	else if (strcmp (con_type, NM_SETTING_BRIDGE_SETTING_NAME) == 0)
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
			if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED && nmc->print_output == NMC_PRINT_PRETTY) {
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

			/* Check for bond or bridge slaves */
			if (   !strcmp (info->con_type, NM_SETTING_BOND_SETTING_NAME)
			    || !strcmp (info->con_type, NM_SETTING_BRIDGE_SETTING_NAME)) {
		
				g_timeout_add_seconds (BB_SLAVES_TIMEOUT, bond_bridge_slaves_check, info);
				return; /* info will be freed in bond_bridge_slaves_check () */
			}
		}
	}
	g_free (info);
}

static NMCResultCode
do_connection_up (NmCli *nmc, int argc, char **argv)
{
	ActivateConnectionInfo *info;
	NMDevice *device = NULL;
	const char *spec_object = NULL;
	gboolean device_found;
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	const char *con_type;
	const char *ifname = NULL;
	const char *ap = NULL;
	const char *nsp = NULL;
	GError *error = NULL;
	gboolean is_virtual = FALSE;
	const char *selector = NULL;
	const char *name;
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
		} else {
			g_string_printf (nmc->return_text, _("Error: No connection specified."));
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto error;
		}
	} else {
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
	}

	connection = find_connection (nmc->system_connections, selector, name);

	if (!connection) {
		g_string_printf (nmc->return_text, _("Error: Unknown connection: %s."), name);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto error;
	}
	next_arg (&argc, &argv);

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

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	con_type = nm_setting_connection_get_connection_type (s_con);

	if (   nm_connection_is_type (connection, NM_SETTING_BOND_SETTING_NAME)
	    || nm_connection_is_type (connection, NM_SETTING_VLAN_SETTING_NAME)
	    || nm_connection_is_type (connection, NM_SETTING_BRIDGE_SETTING_NAME))
		is_virtual = TRUE;

	device_found = find_device_for_connection (nmc, connection, ifname, ap, nsp, &device, &spec_object, &error);
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
	nmc->nowait_flag = (nmc->timeout == 0);
	nmc->should_wait = TRUE;

	info = g_malloc0 (sizeof (ActivateConnectionInfo));
	info->nmc = nmc;
	info->device = device;
	info->con_type = con_type;

	nm_client_activate_connection (nmc->client,
	                               connection,
	                               device,
	                               spec_object,
	                               activate_connection_cb,
	                               info);

	/* Start progress indication */
	if (nmc->print_output == NMC_PRINT_PRETTY)
		progress_id = g_timeout_add (120, progress_cb, "preparing");

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
} NameItem;

/* Available connection types */
static const NameItem nmc_valid_connection_types[] = {
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet"  },
	{ NM_SETTING_WIRELESS_SETTING_NAME,   "wifi"      },
	{ NM_SETTING_WIMAX_SETTING_NAME,      NULL        },
	{ NM_SETTING_GSM_SETTING_NAME,        NULL        },
	{ NM_SETTING_CDMA_SETTING_NAME,       NULL        },
	{ NM_SETTING_INFINIBAND_SETTING_NAME, NULL        },
	{ NM_SETTING_ADSL_SETTING_NAME,       NULL        },
	{ NM_SETTING_BLUETOOTH_SETTING_NAME,  NULL        },
	{ NM_SETTING_VPN_SETTING_NAME,        NULL        },
	{ NM_SETTING_OLPC_MESH_SETTING_NAME,  "olpc-mesh" },
	{ NM_SETTING_VLAN_SETTING_NAME,       NULL        },
	{ NM_SETTING_BOND_SETTING_NAME,       NULL        },
	{ NM_SETTING_BRIDGE_SETTING_NAME,     NULL        },
	{ "bond-slave",                       NULL        },
	{ "bridge-slave",                     NULL        },
	{ NULL, NULL }
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

/*----------------------------------------------------------------------------*/

static gboolean
check_and_convert_mac (const char *mac,
                       GByteArray **mac_array,
                       int type,
                       const char *keyword,
                       GError **error)
{
	g_return_val_if_fail (mac_array != NULL && *mac_array == NULL, FALSE);

	if (mac) {
		*mac_array = nm_utils_hwaddr_atoba (mac, type);
		if (!*mac_array) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("Error: '%s': '%s' is not a valid %s MAC address."),
			             keyword, mac, type == ARPHRD_INFINIBAND ? _("InfiniBand") : "");
			return FALSE;
		}
	}
	return TRUE;
}

static char *
unique_bond_bridge_ifname (GSList *list, const char *type,  const char *try_name)
{
	NMConnection *connection;
	NMSetting *setting;
	char *new_name;
	unsigned int num = 1;
	GSList *iterator = list;
	const char *ifname_property;
	char *ifname_val = NULL;

	ifname_property = strcmp (type, NM_SETTING_BOND_SETTING_NAME) == 0 ?
	                    NM_SETTING_BOND_INTERFACE_NAME :
	                    NM_SETTING_BRIDGE_INTERFACE_NAME;

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
		             _("Error: '%s': '%s' is not valid; use <%d-%d>."),
		             nmc_arg, str, pspec->minimum, pspec->maximum);
		return FALSE;
	}
	return TRUE;
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
		const char *mtu = NULL;
		unsigned long mtu_int;
		const char *mac = NULL;
		const char *cloned_mac = NULL;
		GByteArray *array = NULL;
		GByteArray *cloned_array = NULL;
		nmc_arg_t exp_args[] = { {"mtu",        TRUE, &mtu,        FALSE},
		                         {"mac",        TRUE, &mac,        FALSE},
		                         {"cloned-mac", TRUE, &cloned_mac, FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (mtu) {
			if (!nmc_string_to_uint (mtu, TRUE, 0, G_MAXUINT32, &mtu_int)) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'mtu': '%s' is not valid."), mtu);
				return FALSE;
			}
		}
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
		if (array)
			g_byte_array_free (array, TRUE);
		if (cloned_array)
			g_byte_array_free (cloned_array, TRUE);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, NM_SETTING_INFINIBAND_SETTING_NAME)) {
		/* Build up the settings required for 'infiniband' */
		const char *mtu = NULL;
		unsigned long mtu_int;
		const char *mac = NULL;
		GByteArray *array = NULL;
		const char *mode = "datagram";  /* 'datagram' mode is default */
		const char *parent = NULL;
		const char *p_key = NULL;
		long p_key_int;
		nmc_arg_t exp_args[] = { {"mtu",            TRUE, &mtu,  FALSE},
		                         {"mac",            TRUE, &mac,  FALSE},
		                         {"transport-mode", TRUE, &mode, FALSE},
		                         {"parent",         TRUE, &mode, FALSE},
		                         {"p-key",          TRUE, &mode, FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (mtu) {
			if (!nmc_string_to_uint (mtu, TRUE, 0, G_MAXUINT32, &mtu_int)) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'mtu': '%s' is not valid."), mtu);
				return FALSE;
			}
		}
		if (!check_and_convert_mac (mac, &array, ARPHRD_INFINIBAND, "mac", error))
			return FALSE;
		if (p_key) {
			gboolean p_key_valid = FALSE;
			if (!strncmp (p_key, "0x", 2))
				p_key_valid = nmc_string_to_int_base (p_key + 2, 16, TRUE, 0, G_MAXUINT16, &p_key_int);
			else
				p_key_valid = nmc_string_to_int (p_key, TRUE, 0, G_MAXUINT16, &p_key_int);
			if (!p_key_valid) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'p-key': '%s' is not valid."), p_key);
				return FALSE;
			}
			if (parent && !nm_utils_iface_valid_name (parent)) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'parent': '%s' is not a valid interface name."), parent);
				return FALSE;
			}
		} else if (parent) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("Error: 'parent': not valid without p-key."));
			return FALSE;
		}

		/* Add 'infiniband' setting */
		s_infiniband = (NMSettingInfiniband *) nm_setting_infiniband_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_infiniband));

		g_object_set (s_infiniband, NM_SETTING_INFINIBAND_TRANSPORT_MODE, mode, NULL);
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

	} else if (!strcmp (con_type, NM_SETTING_WIRELESS_SETTING_NAME)) {
		/* Build up the settings required for 'wifi' */
		gboolean success = FALSE;
		char *ssid_ask = NULL;
		const char *ssid = NULL;
		GByteArray *ssid_arr = NULL;
		const char *mtu = NULL;
		unsigned long mtu_int;
		const char *mac = NULL;
		GByteArray *mac_array = NULL;
		const char *cloned_mac = NULL;
		GByteArray *cloned_mac_array = NULL;
		nmc_arg_t exp_args[] = { {"ssid",       TRUE, &ssid,       !ask},
		                         {"mtu",        TRUE, &mtu,        FALSE},
		                         {"mac",        TRUE, &mac,        FALSE},
		                         {"cloned-mac", TRUE, &cloned_mac, FALSE},
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
		if (mtu) {
			if (!nmc_string_to_uint (mtu, TRUE, 0, G_MAXUINT32, &mtu_int)) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'mtu': '%s' is not valid."), mtu);
				return FALSE;
			}
		}
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
		const char *nsp_name = NULL;
		char *nsp_name_ask = NULL;
		const char *mac = NULL;
		GByteArray *mac_array = NULL;
		nmc_arg_t exp_args[] = { {"nsp", TRUE, &nsp_name, !ask},
		                         {"mac", TRUE, &mac,      FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (!nsp_name && ask)
			nsp_name = nsp_name_ask = nmc_get_user_input (_("WiMAX NSP name: "));
		if (!nsp_name) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'nsp' is required."));
			return FALSE;
		}
		if (!check_and_convert_mac (mac, &mac_array, ARPHRD_ETHER, "mac", error)) {
			g_free (nsp_name_ask);
			return FALSE;
		}

		/* Add 'wimax' setting */
		s_wimax = (NMSettingWimax *) nm_setting_wimax_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wimax));
		g_object_set (s_wimax, NM_SETTING_WIMAX_NETWORK_NAME, nsp_name, NULL);

		if (mac_array) {
			g_object_set (s_wimax, NM_SETTING_WIMAX_MAC_ADDRESS, mac_array, NULL);
			g_byte_array_free (mac_array, TRUE);
		}

		g_free (nsp_name_ask);

	} else if (   !strcmp (con_type, NM_SETTING_GSM_SETTING_NAME)
	           || !strcmp (con_type, NM_SETTING_CDMA_SETTING_NAME)) {
		/* Build up the settings required for 'gsm' or 'cdma' mobile broadband */
		const char *apn = NULL;
		char *apn_ask = NULL;
		const char *user = NULL;
		const char *password = NULL;
		gboolean is_gsm;
		int i = 0;
		nmc_arg_t gsm_args[] = { {NULL}, {NULL}, {NULL}, /* placeholders */
		                         {NULL} };

		is_gsm = !strcmp (con_type, NM_SETTING_GSM_SETTING_NAME);

		if (is_gsm)
			gsm_args[i++] = (nmc_arg_t) {"apn", TRUE, &apn, !ask};
		gsm_args[i++] = (nmc_arg_t) {"user",     TRUE, &user,     FALSE};
		gsm_args[i++] = (nmc_arg_t) {"password", TRUE, &password, FALSE};
		gsm_args[i++] = (nmc_arg_t) {NULL};

		if (!nmc_parse_args (gsm_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (!apn && ask && is_gsm)
			apn = apn_ask = nmc_get_user_input (_("APN: "));
		if (!apn && is_gsm) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'apn' is required."));
			return FALSE;
		}

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

	} else if (!strcmp (con_type, NM_SETTING_BLUETOOTH_SETTING_NAME)) {
		/* Build up the settings required for 'bluetooth' */
		const char *addr = NULL;
		char *addr_ask = NULL;
		const char *bt_type = NM_SETTING_BLUETOOTH_TYPE_PANU;  /* 'panu' is default */
		GByteArray *array = NULL;
		nmc_arg_t exp_args[] = { {"addr",    TRUE, &addr,    !ask},
		                         {"bt-type", TRUE, &bt_type, FALSE},
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

		/* Add 'bluetooth' setting */
		s_bt = (NMSettingBluetooth *) nm_setting_bluetooth_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_bt));

		if (!check_and_convert_mac (addr, &array, ARPHRD_ETHER, "addr", error)) {
			g_free (addr_ask);
			return FALSE;
		}
		if (array) {
			g_object_set (s_bt, NM_SETTING_BLUETOOTH_BDADDR, array, NULL);
			g_byte_array_free (array, TRUE);
		}
		g_free (addr_ask);

		/* 'dun' type requires adding 'gsm' or 'cdma' setting */
		if (   !strcmp (bt_type, NM_SETTING_BLUETOOTH_TYPE_DUN)
		    || !strcmp (bt_type, NM_SETTING_BLUETOOTH_TYPE_DUN"-gsm")) {
			bt_type = NM_SETTING_BLUETOOTH_TYPE_DUN;
			s_gsm = (NMSettingGsm *) nm_setting_gsm_new ();
			nm_connection_add_setting (connection, NM_SETTING (s_gsm));
			g_object_set (s_gsm, NM_SETTING_GSM_NUMBER, "*99#", NULL);
//			g_object_set (s_gsm, NM_SETTING_GSM_APN, "FIXME", NULL;

		} else if (!strcmp (bt_type, NM_SETTING_BLUETOOTH_TYPE_DUN"-cdma")) {
			bt_type = NM_SETTING_BLUETOOTH_TYPE_DUN;
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
			return FALSE;
		}
		g_object_set (s_bt, NM_SETTING_BLUETOOTH_TYPE, bt_type, NULL);

	} else if (!strcmp (con_type, NM_SETTING_VLAN_SETTING_NAME)) {
		/* Build up the settings required for 'vlan' */
		gboolean success = FALSE;
		const char *ifname = NULL;
		const char *parent = NULL;
		char *parent_ask = NULL;
		const char *vlan_id = NULL;
		char *vlan_id_ask = NULL;
		unsigned long id = 0;
		const char *flags = NULL;
		unsigned long flags_int = 0;
		const char *ingress = NULL, *egress = NULL;
		char **ingress_arr = NULL, **egress_arr = NULL, **p;
		const char *mtu = NULL;
		unsigned long mtu_int;
		GByteArray *addr_array = NULL;
		nmc_arg_t exp_args[] = { {"dev",     TRUE, &parent,  !ask},
		                         {"id",      TRUE, &vlan_id, !ask},
		                         {"flags",   TRUE, &flags,   FALSE},
		                         {"ingress", TRUE, &ingress, FALSE},
		                         {"egress",  TRUE, &egress,  FALSE},
		                         {"mtu",     TRUE, &mtu,     FALSE},
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

		/* ifname is taken from connection's ifname */
		ifname = nm_setting_connection_get_interface_name (s_con);

		if (mtu) {
			if (!nmc_string_to_uint (mtu, TRUE, 0, G_MAXUINT32, &mtu_int)) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'mtu': '%s' is not valid."), mtu);
				goto cleanup_vlan;
			}
		}
		if (flags) {
			if (!nmc_string_to_uint (flags, TRUE, 0, 7, &flags_int)) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'flags': '%s' is not valid; use <0-7>."),
				             flags);
				goto cleanup_vlan;
			}
		}
		if (ingress) {
			GError *err = NULL;
			if (!(ingress_arr = nmc_vlan_parse_priority_maps (ingress, NM_VLAN_INGRESS_MAP, &err))) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'ingress': '%s' is not valid; %s "),
				             ingress,  err->message);
				g_clear_error (&err);
				goto cleanup_vlan;
			}
		}
		if (egress) {
			GError *err = NULL;
			if (!(egress_arr = nmc_vlan_parse_priority_maps (egress, NM_VLAN_EGRESS_MAP, &err))) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'egress': '%s' is not valid; %s "),
				             egress, err->message);
				g_clear_error (&err);
				goto cleanup_vlan;
			}
		}

		/* Add 'vlan' setting */
		s_vlan = (NMSettingVlan *) nm_setting_vlan_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_vlan));

		/* Add 'wired' setting if necessary */
		if (mtu || addr_array) {
			s_wired = (NMSettingWired *) nm_setting_wired_new ();
			nm_connection_add_setting (connection, NM_SETTING (s_wired));

			if (mtu)
				g_object_set (s_wired, NM_SETTING_WIRED_MTU, (guint32) mtu_int, NULL);
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
			g_object_set (s_vlan, NM_SETTING_VLAN_FLAGS, (guint32) flags_int, NULL);
		for (p = ingress_arr; p && *p; p++)
			nm_setting_vlan_add_priority_str (s_vlan, NM_VLAN_INGRESS_MAP, *p);
		for (p = egress_arr; p && *p; p++)
			nm_setting_vlan_add_priority_str (s_vlan, NM_VLAN_EGRESS_MAP, *p);

		success = TRUE;
cleanup_vlan:
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
		char *bond_ifname = NULL;
		const char *ifname = NULL;
		const char *bond_mode = NULL;
		const char *bond_miimon = NULL;
		const char *bond_downdelay = NULL;
		const char *bond_updelay = NULL;
		const char *bond_arpinterval = NULL;
		const char *bond_arpiptarget = NULL;
		nmc_arg_t exp_args[] = { {"mode",          TRUE, &bond_mode,        FALSE},
		                         {"miimon",        TRUE, &bond_miimon,      FALSE},
		                         {"downdelay",     TRUE, &bond_downdelay,   FALSE},
		                         {"updelay",       TRUE, &bond_updelay,     FALSE},
		                         {"arp-interval",  TRUE, &bond_arpinterval, FALSE},
		                         {"arp-ip-target", TRUE, &bond_arpiptarget, FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		/* Use connection's ifname as 'bond' ifname if exists, else generate one */
		ifname = nm_setting_connection_get_interface_name (s_con);
		if (!ifname)
			bond_ifname = unique_bond_bridge_ifname (all_connections,
			                                         NM_SETTING_BOND_SETTING_NAME,
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
			if (!(bond_mode = nmc_bond_validate_mode (bond_mode, &err))) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'mode': %s."), err->message);
				g_clear_error (&err);
				g_free (bond_ifname);
				return FALSE;
			}
			nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MODE, bond_mode);
		}
		if (bond_miimon)
			nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MIIMON, bond_miimon);
		if (bond_downdelay)
			nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY, bond_downdelay);
		if (bond_updelay)
			nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_UPDELAY, bond_updelay);
		if (bond_arpinterval)
			nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ARP_INTERVAL, bond_arpinterval);
		if (bond_arpiptarget)
			nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ARP_IP_TARGET, bond_arpiptarget);

		g_free (bond_ifname);

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

	} else if (!strcmp (con_type, NM_SETTING_BRIDGE_SETTING_NAME)) {
		/* Build up the settings required for 'bridge' */
		gboolean success = FALSE;
		char *bridge_ifname = NULL;
		const char *ifname = NULL;
		const char *stp = NULL;
		const char *priority = NULL;
		const char *fwd_delay = NULL;
		const char *hello_time = NULL;
		const char *max_age = NULL;
		const char *ageing_time = NULL;
		gboolean stp_bool;
		unsigned long stp_prio_int, fwd_delay_int, hello_time_int,
		              max_age_int, ageing_time_int;
		nmc_arg_t exp_args[] = { {"stp",           TRUE, &stp,         FALSE},
		                         {"priority",      TRUE, &priority,    FALSE},
		                         {"forward-delay", TRUE, &fwd_delay,   FALSE},
		                         {"hello-time",    TRUE, &hello_time,  FALSE},
		                         {"max-age",       TRUE, &max_age,     FALSE},
		                         {"ageing-time",   TRUE, &ageing_time, FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		/* Use connection's ifname as 'bridge' ifname if exists, else generate one */
		ifname = nm_setting_connection_get_interface_name (s_con);
		if (!ifname)
			bridge_ifname = unique_bond_bridge_ifname (all_connections,
			                                           NM_SETTING_BRIDGE_SETTING_NAME,
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
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, "bridge-slave")) {
		/* Build up the settings required for 'bridge-slave' */
		gboolean success = FALSE;
		const char *master = NULL;
		char *master_ask = NULL;
		const char *type = NULL;
		const char *priority = NULL;
		const char *path_cost = NULL;
		const char *hairpin = NULL;
		unsigned long prio_int, path_cost_int;
		gboolean hairpin_bool;
		nmc_arg_t exp_args[] = { {"master",    TRUE, &master,    !ask},
		                         {"type",      TRUE, &type,      FALSE},
		                         {"priority",  TRUE, &priority,  FALSE},
		                         {"path-cost", TRUE, &path_cost, FALSE},
		                         {"hairpin",   TRUE, &hairpin,   FALSE},
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
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, NM_SETTING_VPN_SETTING_NAME)) {
		/* Build up the settings required for 'vpn' */
		const char *valid_vpns[] = { "openvpn", "vpnc", "pptp", "openconnect", "openswan", NULL };
		const char *vpn_type = NULL;
		char *vpn_type_ask = NULL;
		const char *user = NULL;
		const char *st;
		char *service_type;
		GError *tmp_err = NULL;
		nmc_arg_t exp_args[] = { {"vpn-type", TRUE, &vpn_type, !ask},
		                         {"user",     TRUE, &user,      FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (!vpn_type && ask)
			vpn_type = vpn_type_ask = nmc_get_user_input (_("VPN type: "));
		if (!vpn_type) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'vpn-type' is required."));
			return FALSE;
		}

		if (!(st = nmc_string_is_valid (vpn_type, valid_vpns, &tmp_err))) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("Error: 'vpn-type': %s."), tmp_err->message);
			g_clear_error (&tmp_err);
			g_free (vpn_type_ask);
			return FALSE;
		}
		service_type = g_strdup_printf ("%s.%s", NM_DBUS_INTERFACE, st);

		/* Add 'vpn' setting */
		s_vpn = (NMSettingVPN *) nm_setting_vpn_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_vpn));

		g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, service_type, NULL);
		g_object_set (s_vpn, NM_SETTING_VPN_USER_NAME, user, NULL);

		g_free (vpn_type_ask);
		g_free (service_type);

	} else if (!strcmp (con_type, NM_SETTING_OLPC_MESH_SETTING_NAME)) {
		/* Build up the settings required for 'olpc' */
		char *ssid_ask = NULL;
		const char *ssid = NULL;
		GByteArray *ssid_arr;
		const char *channel = NULL;
		unsigned long chan;
		const char *dhcp_anycast = NULL;
		GByteArray *array = NULL;
		nmc_arg_t exp_args[] = { {"ssid",         TRUE, &ssid,         !ask},
		                         {"channel",      TRUE, &channel,      FALSE},
		                         {"dhcp-anycast", TRUE, &dhcp_anycast, FALSE},
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

		if (channel) {
			if (!nmc_string_to_uint (channel, TRUE, 1, 13, &chan)) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'channel': '%s' is not valid; use <1-13>."),
				             channel);
				g_free (ssid_ask);
				return FALSE;
			}
		}
		if (!check_and_convert_mac (dhcp_anycast, &array, ARPHRD_ETHER, "dhcp-anycast", error)) {
			g_free (ssid_ask);
			return FALSE;
		}

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
		g_free (ssid_ask);

	} else {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: '%s' is a not valid connection type."),
		             con_type);
		return FALSE;
	}

	/* Read and add IP configuration */
	if (   strcmp (con_type, "bond-slave") != 0
	    && strcmp (con_type, "bridge-slave") != 0) {

		NMSettingIP4Config *s_ip4 = NULL;
		NMSettingIP6Config *s_ip6 = NULL;
		NMIP4Address *ip4addr = NULL;
		NMIP6Address *ip6addr = NULL;
		gboolean ipv4_added = FALSE;
		gboolean ipv6_added = FALSE;
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

			if (ip4) {
				ip4addr = nmc_parse_and_build_ip4_address (ip4, gw4, error);
				if (!ip4addr) {
					g_prefix_error (error, _("Error: "));
					return FALSE;
				}
			}
			if (ip4addr) {
				if (!ipv4_added) {
					s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
					nm_connection_add_setting (connection, NM_SETTING (s_ip4));
					g_object_set (s_ip4,
					              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
					              NULL);
					ipv4_added = TRUE;
				}
				nm_setting_ip4_config_add_address (s_ip4, ip4addr);
				nm_ip4_address_unref (ip4addr);
				ip4addr = NULL;
			}

			if (ip6) {
				ip6addr = nmc_parse_and_build_ip6_address (ip6, gw6, error);
				if (!ip6addr) {
					g_prefix_error (error, _("Error: "));
					return FALSE;
				}
			}
			if (ip6addr) {
				if (!ipv6_added) {
					s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
					nm_connection_add_setting (connection, NM_SETTING (s_ip6));
					g_object_set (s_ip6,
					              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
					              NULL);
					ipv6_added = TRUE;
				}
				nm_setting_ip6_config_add_address (s_ip6, ip6addr);
				nm_ip6_address_unref (ip6addr);
				ip6addr = NULL;
			}
		}
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
		if (nmc->print_output == NMC_PRINT_PRETTY)
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

	/* ifname is mandatory for all connection types except virtual ones (bond, bridge, vlan) */
	if (   strcmp (type, NM_SETTING_BOND_SETTING_NAME) == 0
	    || strcmp (type, NM_SETTING_BRIDGE_SETTING_NAME) == 0
	    || strcmp (type, NM_SETTING_VLAN_SETTING_NAME) == 0)
		ifname_mandatory = FALSE;

	if (!ifname && ifname_mandatory && nmc->ask)
		ifname = ifname_ask = nmc_get_user_input (_("Interface name: "));
	if (!ifname && ifname_mandatory) {
		g_string_printf (nmc->return_text, _("Error: 'ifname' argument is required."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}
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
		if (matches (*argv, "show") == 0) {
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
		else if (matches(*argv, "delete") == 0) {
			nmc->return_value = do_connection_delete (nmc, argc-1, argv+1);
		}
		else if (matches(*argv, "reload") == 0) {
			nmc->return_value = do_connection_reload (nmc, argc-1, argv+1);
		}
		else if (nmc_arg_is_help (*argv)) {
			usage ();
			nmc->should_wait = FALSE;
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
