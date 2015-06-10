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

#include "config.h"

#include <glib.h>
#include <glib/gi18n.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <netinet/ether.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "utils.h"
#include "common.h"
#include "settings.h"
#include "connections.h"
#include "nm-secret-agent-simple.h"
#include "polkit-agent.h"

/* define some prompts for connection editor */
#define EDITOR_PROMPT_SETTING  _("Setting name? ")
#define EDITOR_PROMPT_PROPERTY _("Property name? ")
#define EDITOR_PROMPT_CON_TYPE _("Enter connection type: ")

/* define some other prompts */
#define PROMPT_CON_TYPE    _("Connection type: ")
#define PROMPT_VPN_TYPE    _("VPN type: ")
#define PROMPT_BOND_MASTER _("Bond master: ")
#define PROMPT_TEAM_MASTER _("Team master: ")
#define PROMPT_BRIDGE_MASTER _("Bridge master: ")
#define PROMPT_CONNECTION  _("Connection (name, UUID, or path): ")
#define PROMPT_CONNECTIONS _("Connection(s) (name, UUID, or path): ")
#define PROMPT_ACTIVE_CONNECTIONS _("Connection(s) (name, UUID, path or apath): ")

static const char *nmc_known_vpns[] =
	{ "openvpn", "vpnc", "pptp", "openconnect", "openswan", "libreswan",
	  "ssh", "l2tp", "iodine", NULL };

/* Available fields for 'connection show' */
static NmcOutputField nmc_fields_con_show[] = {
	{"NAME",            N_("NAME"),           25},  /* 0 */
	{"UUID",            N_("UUID"),           38},  /* 1 */
	{"TYPE",            N_("TYPE"),           17},  /* 2 */
	{"TIMESTAMP",       N_("TIMESTAMP"),      12},  /* 3 */
	{"TIMESTAMP-REAL",  N_("TIMESTAMP-REAL"), 34},  /* 4 */
	{"AUTOCONNECT",     N_("AUTOCONNECT"),    13},  /* 5 */
	{"AUTOCONNECT-PRIORITY", N_("AUTOCONNECT-PRIORITY"), 10},  /* 6 */
	{"READONLY",        N_("READONLY"),       10},  /* 7 */
	{"DBUS-PATH",       N_("DBUS-PATH"),      42},  /* 8 */
	{"ACTIVE",          N_("ACTIVE"),         10},  /* 9 */
	{"DEVICE",          N_("DEVICE"),         10},  /* 10 */
	{"STATE",           N_("STATE"),          12},  /* 11 */
	{"ACTIVE-PATH",     N_("ACTIVE-PATH"),    51},  /* 12 */
	{NULL,              NULL,                  0}
};
#define NMC_FIELDS_CON_SHOW_ALL     "NAME,UUID,TYPE,TIMESTAMP,TIMESTAMP-REAL,AUTOCONNECT,AUTOCONNECT-PRIORITY,READONLY,DBUS-PATH,"\
                                    "ACTIVE,DEVICE,STATE,ACTIVE-PATH"
#define NMC_FIELDS_CON_SHOW_COMMON  "NAME,UUID,TYPE,DEVICE"

/* Helper macro to define fields */
#define SETTING_FIELD(setting, props) { setting, N_(setting), 0, props, NULL, FALSE, FALSE, 0 }

/* defined in settings.c */
extern NmcOutputField nmc_fields_setting_connection[];
extern NmcOutputField nmc_fields_setting_wired[];
extern NmcOutputField nmc_fields_setting_8021X[];
extern NmcOutputField nmc_fields_setting_wireless[];
extern NmcOutputField nmc_fields_setting_wireless_security[];
extern NmcOutputField nmc_fields_setting_ip4_config[];
extern NmcOutputField nmc_fields_setting_ip6_config[];
extern NmcOutputField nmc_fields_setting_serial[];
extern NmcOutputField nmc_fields_setting_ppp[];
extern NmcOutputField nmc_fields_setting_pppoe[];
extern NmcOutputField nmc_fields_setting_adsl[];
extern NmcOutputField nmc_fields_setting_gsm[];
extern NmcOutputField nmc_fields_setting_cdma[];
extern NmcOutputField nmc_fields_setting_bluetooth[];
extern NmcOutputField nmc_fields_setting_olpc_mesh[];
extern NmcOutputField nmc_fields_setting_vpn[];
extern NmcOutputField nmc_fields_setting_wimax[];
extern NmcOutputField nmc_fields_setting_infiniband[];
extern NmcOutputField nmc_fields_setting_bond[];
extern NmcOutputField nmc_fields_setting_vlan[];
extern NmcOutputField nmc_fields_setting_bridge[];
extern NmcOutputField nmc_fields_setting_bridge_port[];
extern NmcOutputField nmc_fields_setting_team[];
extern NmcOutputField nmc_fields_setting_team_port[];
extern NmcOutputField nmc_fields_setting_dcb[];

/* Available settings for 'connection show <con>' - profile part */
static NmcOutputField nmc_fields_settings_names[] = {
	SETTING_FIELD (NM_SETTING_CONNECTION_SETTING_NAME,        nmc_fields_setting_connection + 1),        /* 0 */
	SETTING_FIELD (NM_SETTING_WIRED_SETTING_NAME,             nmc_fields_setting_wired + 1),             /* 1 */
	SETTING_FIELD (NM_SETTING_802_1X_SETTING_NAME,            nmc_fields_setting_8021X + 1),             /* 2 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SETTING_NAME,          nmc_fields_setting_wireless + 1),          /* 3 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, nmc_fields_setting_wireless_security + 1), /* 4 */
	SETTING_FIELD (NM_SETTING_IP4_CONFIG_SETTING_NAME,        nmc_fields_setting_ip4_config + 1),        /* 5 */
	SETTING_FIELD (NM_SETTING_IP6_CONFIG_SETTING_NAME,        nmc_fields_setting_ip6_config + 1),        /* 6 */
	SETTING_FIELD (NM_SETTING_SERIAL_SETTING_NAME,            nmc_fields_setting_serial + 1),            /* 7 */
	SETTING_FIELD (NM_SETTING_PPP_SETTING_NAME,               nmc_fields_setting_ppp + 1),               /* 8 */
	SETTING_FIELD (NM_SETTING_PPPOE_SETTING_NAME,             nmc_fields_setting_pppoe + 1),             /* 9 */
	SETTING_FIELD (NM_SETTING_GSM_SETTING_NAME,               nmc_fields_setting_gsm + 1),               /* 10 */
	SETTING_FIELD (NM_SETTING_CDMA_SETTING_NAME,              nmc_fields_setting_cdma + 1),              /* 11 */
	SETTING_FIELD (NM_SETTING_BLUETOOTH_SETTING_NAME,         nmc_fields_setting_bluetooth + 1),         /* 12 */
	SETTING_FIELD (NM_SETTING_OLPC_MESH_SETTING_NAME,         nmc_fields_setting_olpc_mesh + 1),         /* 13 */
	SETTING_FIELD (NM_SETTING_VPN_SETTING_NAME,               nmc_fields_setting_vpn + 1),               /* 14 */
	SETTING_FIELD (NM_SETTING_WIMAX_SETTING_NAME,             nmc_fields_setting_wimax + 1),             /* 15 */
	SETTING_FIELD (NM_SETTING_INFINIBAND_SETTING_NAME,        nmc_fields_setting_infiniband + 1),        /* 16 */
	SETTING_FIELD (NM_SETTING_BOND_SETTING_NAME,              nmc_fields_setting_bond + 1),              /* 17 */
	SETTING_FIELD (NM_SETTING_VLAN_SETTING_NAME,              nmc_fields_setting_vlan + 1),              /* 18 */
	SETTING_FIELD (NM_SETTING_ADSL_SETTING_NAME,              nmc_fields_setting_adsl + 1),              /* 19 */
	SETTING_FIELD (NM_SETTING_BRIDGE_SETTING_NAME,            nmc_fields_setting_bridge + 1),            /* 20 */
	SETTING_FIELD (NM_SETTING_BRIDGE_PORT_SETTING_NAME,       nmc_fields_setting_bridge_port + 1),       /* 21 */
	SETTING_FIELD (NM_SETTING_TEAM_SETTING_NAME,              nmc_fields_setting_team + 1),              /* 22 */
	SETTING_FIELD (NM_SETTING_TEAM_PORT_SETTING_NAME,         nmc_fields_setting_team_port + 1),         /* 23 */
	SETTING_FIELD (NM_SETTING_DCB_SETTING_NAME,               nmc_fields_setting_dcb + 1),               /* 24 */
	{NULL, NULL, 0, NULL, NULL, FALSE, FALSE, 0}
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
                                         NM_SETTING_TEAM_PORT_SETTING_NAME"," \
                                         NM_SETTING_DCB_SETTING_NAME
#define NMC_FIELDS_SETTINGS_NAMES_ALL    NMC_FIELDS_SETTINGS_NAMES_ALL_X

/* Active connection data */
/* Available fields for GENERAL group */
static NmcOutputField nmc_fields_con_active_details_general[] = {
	{"GROUP",         N_("GROUP"),         9},  /* 0 */
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
#define NMC_FIELDS_CON_ACTIVE_DETAILS_GENERAL_ALL  "GROUP,NAME,UUID,DEVICES,STATE,DEFAULT,DEFAULT6,"\
                                                   "VPN,ZONE,DBUS-PATH,CON-PATH,SPEC-OBJECT,MASTER-PATH"

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

/* defined in common.c */
extern NmcOutputField nmc_fields_ip4_config[];
extern NmcOutputField nmc_fields_ip6_config[];
extern NmcOutputField nmc_fields_dhcp4_config[];
extern NmcOutputField nmc_fields_dhcp6_config[];

/* Available fields for 'connection show <con>' - active part */
static NmcOutputField nmc_fields_con_active_details_groups[] = {
	{"GENERAL",  N_("GENERAL"), 0, nmc_fields_con_active_details_general + 1},  /* 0 */
	{"IP4",      N_("IP4"),     0, nmc_fields_ip4_config + 1                },  /* 1 */
	{"DHCP4",    N_("DHCP4"),   0, nmc_fields_dhcp4_config + 1              },  /* 2 */
	{"IP6",      N_("IP6"),     0, nmc_fields_ip6_config + 1                },  /* 3 */
	{"DHCP6",    N_("DHCP6"),   0, nmc_fields_dhcp6_config + 1              },  /* 4 */
	{"VPN",      N_("VPN"),     0, nmc_fields_con_active_details_vpn + 1    },  /* 5 */
	{NULL, NULL, 0, NULL}
};
#define NMC_FIELDS_CON_ACTIVE_DETAILS_ALL  "GENERAL,IP4,DHCP4,IP6,DHCP6,VPN"

/* Pseudo group names for 'connection show <con>' */
/* e.g.: nmcli -f profile con show my-eth0 */
/* e.g.: nmcli -f active con show my-eth0 */
#define CON_SHOW_DETAIL_GROUP_PROFILE "profile"
#define CON_SHOW_DETAIL_GROUP_ACTIVE  "active"

/* glib main loop variable - defined in nmcli.c */
extern GMainLoop *loop;

static guint progress_id = 0;  /* ID of event source for displaying progress */

/* for readline TAB completion in editor */
typedef struct {
	NmCli *nmc;
	char *con_type;
	NMConnection *connection;
	NMSetting *setting;
	const char *property;
} TabCompletionInfo;
static TabCompletionInfo nmc_tab_completion = {NULL, NULL, NULL, NULL};

/* Global variable defined in nmcli.c - used for TAB completion */
extern NmCli nm_cli;

static char *gen_connection_types (const char *text, int state);

static void
usage (void)
{
	g_printerr (_("Usage: nmcli connection { COMMAND | help }\n\n"
	              "COMMAND := { show | up | down | add | modify | edit | delete | reload | load }\n\n"
	              "  show [--active] [--order <order spec>]\n"
	              "  show [--active] [--show-secrets] [id | uuid | path | apath] <ID> ...\n\n"
	              "  up [[id | uuid | path] <ID>] [ifname <ifname>] [ap <BSSID>] [passwd-file <file with passwords>]\n\n"
	              "  down [id | uuid | path | apath] <ID> ...\n\n"
	              "  add COMMON_OPTIONS TYPE_SPECIFIC_OPTIONS IP_OPTIONS\n\n"
	              "  modify [--temporary] [id | uuid | path] <ID> ([+|-]<setting>.<property> <value>)+\n\n"
	              "  edit [id | uuid | path] <ID>\n"
	              "  edit [type <new_con_type>] [con-name <new_con_name>]\n\n"
	              "  delete [id | uuid | path] <ID>\n\n"
	              "  reload\n\n"
	              "  load <filename> [ <filename>... ]\n\n"));
}

static void
usage_connection_show (void)
{
	g_printerr (_("Usage: nmcli connection show { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [--active] [--order <order spec>]\n"
	              "\n"
	              "List in-memory and on-disk connection profiles, some of which may also be\n"
	              "active if a device is using that connection profile. Without a parameter, all\n"
	              "profiles are listed. When --active option is specified, only the active\n"
	              "profiles are shown. --order allows custom connection ordering (see manual page).\n"
	              "\n"
	              "ARGUMENTS := [--active] [--show-secrets] [id | uuid | path | apath] <ID> ...\n"
	              "\n"
	              "Show details for specified connections. By default, both static configuration\n"
	              "and active connection data are displayed. It is possible to filter the output\n"
	              "using global '--fields' option. Refer to the manual page for more information.\n"
	              "When --active option is specified, only the active profiles are taken into\n"
	              "account. --show-secrets option will reveal associated secrets as well.\n"));
}

static void
usage_connection_up (void)
{
	g_printerr (_("Usage: nmcli connection up { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [id | uuid | path] <ID> [ifname <ifname>] [ap <BSSID>] [nsp <name>] [passwd-file <file with passwords>]\n"
	              "\n"
	              "Activate a connection on a device. The profile to activate is identified by its\n"
	              "name, UUID or D-Bus path.\n"
	              "\n"
	              "ARGUMENTS := ifname <ifname> [ap <BSSID>] [nsp <name>] [passwd-file <file with passwords>]\n"
	              "\n"
	              "Activate a device with a connection. The connection profile is selected\n"
	              "automatically by NetworkManager.\n"
	              "\n"
	              "ifname      - specifies the device to active the connection on\n"
	              "ap          - specifies AP to connect to (only valid for Wi-Fi)\n"
	              "nsp         - specifies NSP to connect to (only valid for WiMAX)\n"
	              "passwd-file - file with password(s) required to activate the connection\n\n"));
}

static void
usage_connection_down (void)
{
	g_printerr (_("Usage: nmcli connection down { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [id | uuid | path | apath] <ID> ...\n"
	              "\n"
	              "Deactivate a connection from a device (without preventing the device from\n"
	              "further auto-activation). The profile to deactivate is identified by its name,\n"
	              "UUID or D-Bus path.\n\n"));
}

static void
usage_connection_add (void)
{
	g_printerr (_("Usage: nmcli connection add { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := COMMON_OPTIONS TYPE_SPECIFIC_OPTIONS IP_OPTIONS\n\n"
	              "  COMMON_OPTIONS:\n"
	              "                  type <type>\n"
	              "                  ifname <interface name> | \"*\"\n"
	              "                  [con-name <connection name>]\n"
	              "                  [autoconnect yes|no]\n\n"
	              "                  [save yes|no]\n\n"
	              "  TYPE_SPECIFIC_OPTIONS:\n"
	              "    ethernet:     [mac <MAC address>]\n"
	              "                  [cloned-mac <cloned MAC address>]\n"
	              "                  [mtu <MTU>]\n\n"
	              "    wifi:         ssid <SSID>\n"
	              "                  [mac <MAC address>]\n"
	              "                  [cloned-mac <cloned MAC address>]\n"
	              "                  [mtu <MTU>]\n"
	              "                  [mode infrastructure|ap|adhoc]\n\n"
	              "    wimax:        [mac <MAC address>]\n"
	              "                  [nsp <NSP>]\n\n"
	              "    pppoe:        username <PPPoE username>\n"
	              "                  [password <PPPoE password>]\n"
	              "                  [service <PPPoE service name>]\n"
	              "                  [mtu <MTU>]\n"
	              "                  [mac <MAC address>]\n\n"
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
	              "                  id <VLAN ID>\n"
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
	              "                  [arp-ip-target <num>]\n"
	              "                  [lacp-rate slow (0) | fast (1)]\n\n"
	              "    bond-slave:   master <master (ifname, or connection UUID or name)>\n\n"
	              "    team:         [config <file>|<raw JSON data>]\n\n"
	              "    team-slave:   master <master (ifname, or connection UUID or name)>\n"
	              "                  [config <file>|<raw JSON data>]\n\n"
	              "    bridge:       [stp yes|no]\n"
	              "                  [priority <num>]\n"
	              "                  [forward-delay <2-30>]\n"
	              "                  [hello-time <1-10>]\n"
	              "                  [max-age <6-40>]\n"
	              "                  [ageing-time <0-1000000>]\n"
	              "                  [multicast-snooping yes|no]\n"
	              "                  [mac <MAC address>]\n\n"
	              "    bridge-slave: master <master (ifname, or connection UUID or name)>\n"
	              "                  [priority <0-63>]\n"
	              "                  [path-cost <1-65535>]\n"
	              "                  [hairpin yes|no]\n\n"
	              "    vpn:          vpn-type vpnc|openvpn|pptp|openconnect|openswan|libreswan|ssh|l2tp|iodine|...\n"
	              "                  [user <username>]\n\n"
	              "    olpc-mesh:    ssid <SSID>\n"
	              "                  [channel <1-13>]\n"
	              "                  [dhcp-anycast <MAC address>]\n\n"
	              "  IP_OPTIONS:\n"
	              "                  [ip4 <IPv4 address>] [gw4 <IPv4 gateway>]\n"
	              "                  [ip6 <IPv6 address>] [gw6 <IPv6 gateway>]\n\n"));
}

static void
usage_connection_modify (void)
{
	g_printerr (_("Usage: nmcli connection modify { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [id | uuid | path] <ID> ([+|-]<setting>.<property> <value>)+\n"
	              "\n"
	              "Modify one or more properties of the connection profile.\n"
	              "The profile is identified by its name, UUID or D-Bus path. For multi-valued\n"
	              "properties you can use optional '+' or '-' prefix to the property name.\n"
	              "The '+' sign allows appending items instead of overwriting the whole value.\n"
	              "The '-' sign allows removing selected items instead of the whole value.\n"
	              "\n"
	              "Examples:\n"
	              "nmcli con mod home-wifi wifi.ssid rakosnicek\n"
	              "nmcli con mod em1-1 ipv4.method manual ipv4.addr \"192.168.1.2/24, 10.10.1.5/8\"\n"
	              "nmcli con mod em1-1 +ipv4.dns 8.8.4.4\n"
	              "nmcli con mod em1-1 -ipv4.dns 1\n"
	              "nmcli con mod em1-1 -ipv6.addr \"abbe::cafe/56\"\n"
	              "nmcli con mod bond0 +bond.options mii=500\n"
	              "nmcli con mod bond0 -bond.options downdelay\n\n"));
}

static void
usage_connection_edit (void)
{
	g_printerr (_("Usage: nmcli connection edit { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [id | uuid | path] <ID>\n"
	              "\n"
	              "Edit an existing connection profile in an interactive editor.\n"
	              "The profile is identified by its name, UUID or D-Bus path\n"
	              "\n"
	              "ARGUMENTS := [type <new connection type>] [con-name <new connection name>]\n"
	              "\n"
	              "Add a new connection profile in an interactive editor.\n\n"));
}

static void
usage_connection_delete (void)
{
	g_printerr (_("Usage: nmcli connection delete { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [id | uuid | path] <ID>\n"
	              "\n"
	              "Delete a connection profile.\n"
	              "The profile is identified by its name, UUID or D-Bus path.\n\n"));
}

static void
usage_connection_reload (void)
{
	g_printerr (_("Usage: nmcli connection reload { help }\n"
	              "\n"
	              "Reload all connection files from disk.\n\n"));
}

static void
usage_connection_load (void)
{
	g_printerr (_("Usage: nmcli connection load { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := <filename> [<filename>...]\n"
	              "\n"
	              "Load/reload one or more connection files from disk. Use this after manually\n"
	              "editing a connection file to ensure that NetworkManager is aware of its latest\n"
	              "state.\n\n"));
}

static gboolean
usage_connection_second_level (const char *cmd)
{
	gboolean ret = TRUE;

	if (matches (cmd, "show") == 0)
		usage_connection_show ();
	else if (matches (cmd, "up") == 0)
		usage_connection_up ();
	else if (matches (cmd, "down") == 0)
		usage_connection_down ();
	else if (matches (cmd, "add") == 0)
		usage_connection_add ();
	else if (matches (cmd, "modify") == 0)
		usage_connection_modify ();
	else if (matches (cmd, "edit") == 0)
		usage_connection_edit ();
	else if (matches (cmd, "delete") == 0)
		usage_connection_delete ();
	else if (matches (cmd, "reload") == 0)
		usage_connection_reload ();
	else if (matches (cmd, "load") == 0)
		usage_connection_load ();
	else
		ret = FALSE;
	return ret;
}

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

static const char *
construct_header_name (const char *base, const char *spec)
{
	static char header_name[128];

	if (spec == NULL)
		return base;

	g_strlcpy (header_name, base, sizeof (header_name));
	g_strlcat (header_name, " (", sizeof (header_name));
	g_strlcat (header_name, spec, sizeof (header_name));
	g_strlcat (header_name, ")", sizeof (header_name));

	return header_name;
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
vpn_connection_state_to_string (NMVpnConnectionState state)
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

/* Caller has to free the returned string */
static char *
get_ac_device_string (NMActiveConnection *active)
{
	GString *dev_str;
	const GPtrArray *devices;
	int i;

	if (!active)
		return NULL;

	/* Get devices of the active connection */
	dev_str = g_string_new (NULL);
	devices = nm_active_connection_get_devices (active);
	for (i = 0; i < devices->len; i++) {
		NMDevice *device = g_ptr_array_index (devices, i);
		const char *dev_iface = nm_device_get_iface (device);

		if (dev_iface) {
			g_string_append (dev_str, dev_iface);
			g_string_append_c (dev_str, ',');
		}
	}
	if (dev_str->len > 0)
		g_string_truncate (dev_str, dev_str->len - 1);  /* Cut off last ',' */

	return g_string_free (dev_str, FALSE);
}

static NMActiveConnection *
get_ac_for_connection (const GPtrArray *active_cons, NMConnection *connection)
{
	const char *con_path, *ac_con_path;
	int i;
	NMActiveConnection *ac = NULL;

	/* Is the connection active? */
	con_path = nm_connection_get_path (connection);
	for (i = 0; i < active_cons->len; i++) {
		NMActiveConnection *candidate = g_ptr_array_index (active_cons, i);
		NMRemoteConnection *con;

		con = nm_active_connection_get_connection (candidate);
		ac_con_path = con ? nm_connection_get_path (NM_CONNECTION (con)) : NULL;
		if (!g_strcmp0 (ac_con_path, con_path)) {
			ac = candidate;
			break;
		}
	}
	return ac;
}

/* Put secrets into local connection. */
static void
update_secrets_in_connection (NMRemoteConnection *remote, NMConnection *local)
{
	GVariant *secrets;
	int i;
	GError *error = NULL;

	for (i = 0; nmc_fields_settings_names[i].name; i++) {
		secrets = nm_remote_connection_get_secrets (remote, nmc_fields_settings_names[i].name, NULL, NULL);
		if (secrets) {
			if (!nm_connection_update_secrets (local, NULL, secrets, &error) && error) {
				g_printerr (_("Error updating secrets for %s: %s\n"),
				            nmc_fields_settings_names[i].name,
				            error->message);
				g_clear_error (&error);
			}
			g_variant_unref (secrets);
		}
	}
}

static gboolean
nmc_connection_profile_details (NMConnection *connection, NmCli *nmc, gboolean secrets)
{
	GError *error = NULL;
	GArray *print_settings_array;
	GPtrArray *prop_array = NULL;
	int i;
	char *fields_str;
	char *fields_all =    NMC_FIELDS_SETTINGS_NAMES_ALL;
	char *fields_common = NMC_FIELDS_SETTINGS_NAMES_ALL;
	const char *base_hdr = _("Connection profile details");
	gboolean was_output = FALSE;

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else
		fields_str = nmc->required_fields;

	print_settings_array = parse_output_fields (fields_str, nmc_fields_settings_names, TRUE, &prop_array, &error);
	if (error) {
		g_string_printf (nmc->return_text, _("Error: 'connection show': %s"), error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return FALSE;
	}
	g_assert (print_settings_array);

	/* Main header */
	nmc->print_fields.header_name = (char *) construct_header_name (base_hdr, nm_connection_get_id (connection));
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTINGS_NAMES_ALL,
	                                                 nmc_fields_settings_names, FALSE, NULL, NULL);

	nmc_fields_settings_names[0].flags = NMC_OF_FLAG_MAIN_HEADER_ONLY;
	print_required_fields (nmc, nmc_fields_settings_names);

	/* Loop through the required settings and print them. */
	for (i = 0; i < print_settings_array->len; i++) {
		NMSetting *setting;
		int section_idx = g_array_index (print_settings_array, int, i);
		const char *prop_name = (const char *) g_ptr_array_index (prop_array, i);

		if (nmc->print_output != NMC_PRINT_TERSE && !nmc->multiline_output && was_output)
			g_print ("\n"); /* Empty line */

		was_output = FALSE;

		/* Remove any previous data */
		nmc_empty_output_fields (nmc);

		setting = nm_connection_get_setting_by_name (connection, nmc_fields_settings_names[section_idx].name);
		if (setting) {
			setting_details (setting, nmc, prop_name, secrets);
			was_output = TRUE;
			continue;
		}
	}

	g_array_free (print_settings_array, TRUE);
	if (prop_array)
		g_ptr_array_free (prop_array, TRUE);

	return TRUE;
}

static NMActiveConnection *
find_active_connection (const GPtrArray *active_cons,
                        const GPtrArray *cons,
                        const char *filter_type,
                        const char *filter_val,
                        int *idx)
{
	int i;
	int start = (idx && *idx > 0) ? *idx : 0;
	const char *path, *a_path, *path_num, *a_path_num;
	const char *id;
	const char *uuid;
	NMRemoteConnection *con;
	NMActiveConnection *found = NULL;

	for (i = start; i < active_cons->len; i++) {
		NMActiveConnection *candidate = g_ptr_array_index (active_cons, i);

		con = nm_active_connection_get_connection (candidate);

		id = nm_active_connection_get_id (candidate);
		uuid = nm_active_connection_get_uuid (candidate);
		path = con ? nm_connection_get_path (NM_CONNECTION (con)) : NULL;
		path_num = path ? strrchr (path, '/') + 1 : NULL;
		a_path = nm_object_get_path (NM_OBJECT (candidate));
		a_path_num = a_path ? strrchr (a_path, '/') + 1 : NULL;

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
		        && (g_strcmp0 (filter_val, a_path) == 0 || (filter_type && g_strcmp0 (filter_val, a_path_num) == 0)))) {
			if (!idx)
				return candidate;
			if (found) {
				*idx = i;
				return found;
			}
			found = candidate;
		}
	}

	if (idx)
		*idx = 0;
	return found;
}

static void
fill_output_connection (NMConnection *connection, NmCli *nmc, gboolean active_only)
{
	NMSettingConnection *s_con;
	guint64 timestamp;
	time_t timestamp_real;
	char *timestamp_str;
	char *timestamp_real_str = "";
	char *prio_str;
	NmcOutputField *arr;
	NMActiveConnection *ac = NULL;
	const char *ac_path = NULL;
	const char *ac_state = NULL;
	NMActiveConnectionState ac_state_int = NM_ACTIVE_CONNECTION_STATE_UNKNOWN;
	char *ac_dev = NULL;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	ac = get_ac_for_connection (nm_client_get_active_connections (nmc->client), connection);
	if (active_only && !ac)
		return;

	if (ac) {
		ac_path = nm_object_get_path (NM_OBJECT (ac));
		ac_state_int = nm_active_connection_get_state (ac);
		ac_state = active_connection_state_to_string (ac_state_int);
		ac_dev = get_ac_device_string (ac);
	}

	/* Obtain field values */
	timestamp = nm_setting_connection_get_timestamp (s_con);
	timestamp_str = g_strdup_printf ("%" G_GUINT64_FORMAT, timestamp);
	if (timestamp) {
		timestamp_real = timestamp;
		timestamp_real_str = g_malloc0 (64);
		strftime (timestamp_real_str, 64, "%c", localtime (&timestamp_real));
	}
	prio_str = g_strdup_printf ("%u", nm_setting_connection_get_autoconnect_priority (s_con));

	arr = nmc_dup_fields_array (nmc_fields_con_show,
	                            sizeof (nmc_fields_con_show),
	                            0);
	/* Show active connections in color */
	if (ac) {
		if (ac_state_int == NM_ACTIVE_CONNECTION_STATE_ACTIVATING)
			set_val_color_all (arr, NMC_TERM_COLOR_YELLOW);
		else if (ac_state_int == NM_ACTIVE_CONNECTION_STATE_ACTIVATED)
			set_val_color_all (arr, NMC_TERM_COLOR_GREEN);
		else if (ac_state_int > NM_ACTIVE_CONNECTION_STATE_ACTIVATED)
			set_val_color_all (arr, NMC_TERM_COLOR_RED);
	}

	set_val_strc (arr, 0, nm_setting_connection_get_id (s_con));
	set_val_strc (arr, 1, nm_setting_connection_get_uuid (s_con));
	set_val_strc (arr, 2, nm_setting_connection_get_connection_type (s_con));
	set_val_str  (arr, 3, timestamp_str);
	set_val_str  (arr, 4, timestamp ? timestamp_real_str : g_strdup (_("never")));
	set_val_strc (arr, 5, nm_setting_connection_get_autoconnect (s_con) ? _("yes") : _("no"));
	set_val_str  (arr, 6, prio_str);
	set_val_strc (arr, 7, nm_setting_connection_get_read_only (s_con) ? _("yes") : _("no"));
	set_val_strc (arr, 8, nm_connection_get_path (connection));
	set_val_strc (arr, 9, ac ? _("yes") : _("no"));
	set_val_str  (arr, 10, ac_dev);
	set_val_strc (arr, 11, ac_state);
	set_val_strc (arr, 12, ac_path);

	g_ptr_array_add (nmc->output_data, arr);
}

static void
fill_output_connection_for_invisible (NMActiveConnection *ac, NmCli *nmc)
{
	NmcOutputField *arr;
	const char *ac_path = NULL;
	const char *ac_state = NULL;
	char *name, *ac_dev = NULL;

	name = g_strdup_printf ("<invisible> %s", nm_active_connection_get_id (ac));
	ac_path = nm_object_get_path (NM_OBJECT (ac));
	ac_state = active_connection_state_to_string (nm_active_connection_get_state (ac));
	ac_dev = get_ac_device_string (ac);

	arr = nmc_dup_fields_array (nmc_fields_con_show,
	                            sizeof (nmc_fields_con_show),
	                            0);

	set_val_str  (arr, 0, name);
	set_val_strc (arr, 1, nm_active_connection_get_uuid (ac));
	set_val_strc (arr, 2, nm_active_connection_get_connection_type (ac));
	set_val_strc (arr, 3, NULL);
	set_val_strc (arr, 4, NULL);
	set_val_strc (arr, 5, NULL);
	set_val_strc (arr, 6, NULL);
	set_val_strc (arr, 7, NULL);
	set_val_strc (arr, 8, NULL);
	set_val_strc (arr, 9, _("yes"));
	set_val_str  (arr, 10, ac_dev);
	set_val_strc (arr, 11, ac_state);
	set_val_strc (arr, 12, ac_path);

	set_val_color_fmt_all (arr, NMC_TERM_FORMAT_DIM);

	g_ptr_array_add (nmc->output_data, arr);
}

static void
fill_output_active_connection (NMActiveConnection *active,
                               NmCli *nmc,
                               gboolean with_group,
                               guint32 o_flags)
{
	NMRemoteConnection *con;
	NMSettingConnection *s_con;
	const GPtrArray *devices;
	GString *dev_str;
	NMActiveConnectionState state;
	NMDevice *master;
	const char *con_path = NULL, *con_zone = NULL;
	int i;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;
	int idx_start = with_group ? 0 : 1;

	con = nm_active_connection_get_connection (active);
	if (con) {
		con_path = nm_connection_get_path (NM_CONNECTION (con));
		s_con = nm_connection_get_setting_connection (NM_CONNECTION (con));
		g_assert (s_con != NULL);
		con_zone = nm_setting_connection_get_zone (s_con);
	}

	state = nm_active_connection_get_state (active);
	master = nm_active_connection_get_master (active);

	/* Get devices of the active connection */
	dev_str = g_string_new (NULL);
	devices = nm_active_connection_get_devices (active);
	for (i = 0; i < devices->len; i++) {
		NMDevice *device = g_ptr_array_index (devices, i);
		const char *dev_iface = nm_device_get_iface (device);

		if (dev_iface) {
			g_string_append (dev_str, dev_iface);
			g_string_append_c (dev_str, ',');
		}
	}
	if (dev_str->len > 0)
		g_string_truncate (dev_str, dev_str->len - 1);  /* Cut off last ',' */

	tmpl = nmc_fields_con_active_details_general;
	tmpl_len = sizeof (nmc_fields_con_active_details_general);
	if (!with_group) {
		tmpl++;
		tmpl_len -= sizeof (NmcOutputField);
	}

	/* Fill field values */
	arr = nmc_dup_fields_array (tmpl, tmpl_len, o_flags);
	if (with_group)
		set_val_strc (arr, 0, nmc_fields_con_active_details_groups[0].name);
	set_val_strc (arr, 1-idx_start, nm_active_connection_get_id (active));
	set_val_strc (arr, 2-idx_start, nm_active_connection_get_uuid (active));
	set_val_str  (arr, 3-idx_start, dev_str->str);
	set_val_strc (arr, 4-idx_start, active_connection_state_to_string (state));
	set_val_strc (arr, 5-idx_start, nm_active_connection_get_default (active) ? _("yes") : _("no"));
	set_val_strc (arr, 6-idx_start, nm_active_connection_get_default6 (active) ? _("yes") : _("no"));
	set_val_strc (arr, 7-idx_start, nm_active_connection_get_specific_object_path (active));
	set_val_strc (arr, 8-idx_start, NM_IS_VPN_CONNECTION (active) ? _("yes") : _("no"));
	set_val_strc (arr, 9-idx_start, nm_object_get_path (NM_OBJECT (active)));
	set_val_strc (arr, 10-idx_start, con_path);
	set_val_strc (arr, 11-idx_start, con_zone);
	set_val_strc (arr, 12-idx_start, master ? nm_object_get_path (NM_OBJECT (master)) : NULL);

	g_ptr_array_add (nmc->output_data, arr);

	g_string_free (dev_str, FALSE);
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
	if (g_strcmp0 (vpn_type, "libreswan") == 0)   return "right";
	if (g_strcmp0 (vpn_type, "ssh") == 0)         return "remote";
	if (g_strcmp0 (vpn_type, "l2tp") == 0)        return "gateway";
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
	if (g_strcmp0 (vpn_type, "libreswan") == 0)   return "leftxauthusername";
	if (g_strcmp0 (vpn_type, "l2tp") == 0)        return "user";
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
nmc_active_connection_details (NMActiveConnection *acon, NmCli *nmc)
{
	GError *error = NULL;
	GArray *print_groups;
	GPtrArray *group_fields = NULL;
	int i;
	char *fields_str;
	char *fields_all =    NMC_FIELDS_CON_ACTIVE_DETAILS_ALL;
	char *fields_common = NMC_FIELDS_CON_ACTIVE_DETAILS_ALL;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;
	const char *base_hdr = _("Activate connection details");
	gboolean was_output = FALSE;

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else
		fields_str = nmc->required_fields;

	print_groups = parse_output_fields (fields_str, nmc_fields_con_active_details_groups, TRUE, &group_fields, &error);
	if (error) {
		g_string_printf (nmc->return_text, _("Error: 'connection show': %s"), error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return FALSE;
	}
	g_assert (print_groups);

	/* Main header */
	nmc->print_fields.header_name = (char *) construct_header_name (base_hdr, nm_active_connection_get_uuid (acon));
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_CON_ACTIVE_DETAILS_ALL,
	                                                 nmc_fields_con_active_details_groups, FALSE, NULL, NULL);

	nmc_fields_con_active_details_groups[0].flags = NMC_OF_FLAG_MAIN_HEADER_ONLY;
	print_required_fields (nmc, nmc_fields_con_active_details_groups);

	/* Loop through the groups and print them. */
	for (i = 0; i < print_groups->len; i++) {
		int group_idx = g_array_index (print_groups, int, i);
		char *group_fld = (char *) g_ptr_array_index (group_fields, i);

		if (nmc->print_output != NMC_PRINT_TERSE && !nmc->multiline_output && was_output)
			g_print ("\n"); /* Empty line */

		was_output = FALSE;

		/* Remove any previous data */
		nmc_empty_output_fields (nmc);

		/* GENERAL */
		if (strcasecmp (nmc_fields_con_active_details_groups[group_idx].name, nmc_fields_con_active_details_groups[0].name) == 0) {
			/* Add field names */
			tmpl = nmc_fields_con_active_details_general;
			tmpl_len = sizeof (nmc_fields_con_active_details_general);
			nmc->print_fields.indices = parse_output_fields (group_fld ? group_fld : NMC_FIELDS_CON_ACTIVE_DETAILS_GENERAL_ALL,
			                                                 tmpl, FALSE, NULL, NULL);
			arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
			g_ptr_array_add (nmc->output_data, arr);

			/* Fill in values */
			fill_output_active_connection (acon, nmc, TRUE, NMC_OF_FLAG_SECTION_PREFIX);

			print_data (nmc);  /* Print all data */

			was_output = TRUE;
		}

		/* IP4 */
		if (strcasecmp (nmc_fields_con_active_details_groups[group_idx].name,  nmc_fields_con_active_details_groups[1].name) == 0) {
			gboolean b1 = FALSE;
			NMIPConfig *cfg4 = nm_active_connection_get_ip4_config (acon);

			b1 = print_ip4_config (cfg4, nmc, "IP4", group_fld);
			was_output = was_output || b1;
		}

		/* DHCP4 */
		if (strcasecmp (nmc_fields_con_active_details_groups[group_idx].name,  nmc_fields_con_active_details_groups[2].name) == 0) {
			gboolean b1 = FALSE;
			NMDhcpConfig *dhcp4 = nm_active_connection_get_dhcp4_config (acon);

			b1 = print_dhcp4_config (dhcp4, nmc, "DHCP4", group_fld);
			was_output = was_output || b1;
		}

		/* IP6 */
		if (strcasecmp (nmc_fields_con_active_details_groups[group_idx].name,  nmc_fields_con_active_details_groups[3].name) == 0) {
			gboolean b1 = FALSE;
			NMIPConfig *cfg6 = nm_active_connection_get_ip6_config (acon);

			b1 = print_ip6_config (cfg6, nmc, "IP6", group_fld);
			was_output = was_output || b1;
		}

		/* DHCP6 */
		if (strcasecmp (nmc_fields_con_active_details_groups[group_idx].name,  nmc_fields_con_active_details_groups[4].name) == 0) {
			gboolean b1 = FALSE;
			NMDhcpConfig *dhcp6 = nm_active_connection_get_dhcp6_config (acon);

			b1 = print_dhcp6_config (dhcp6, nmc, "DHCP6", group_fld);
			was_output = was_output || b1;
		}

		/* VPN */
		if (NM_IS_VPN_CONNECTION (acon) &&
		    strcasecmp (nmc_fields_con_active_details_groups[group_idx].name,  nmc_fields_con_active_details_groups[5].name) == 0) {
			NMConnection *con;
			NMSettingConnection *s_con;
			NMSettingVpn *s_vpn;
			NMVpnConnectionState vpn_state;
			char *type_str, *banner_str = NULL, *vpn_state_str;
			const char *banner;
			const char *username = NULL;
			char **vpn_data_array = NULL;
			guint32 items_num;

			con = NM_CONNECTION (nm_active_connection_get_connection (acon));

			s_con = nm_connection_get_setting_connection (con);
			g_assert (s_con != NULL);

			tmpl = nmc_fields_con_active_details_vpn;
			tmpl_len = sizeof (nmc_fields_con_active_details_vpn);
			nmc->print_fields.indices = parse_output_fields (group_fld ? group_fld : NMC_FIELDS_CON_ACTIVE_DETAILS_VPN_ALL,
			                                                 tmpl, FALSE, NULL, NULL);
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
			banner = nm_vpn_connection_get_banner (NM_VPN_CONNECTION (acon));
			if (banner)
				banner_str = g_strescape (banner, "");
			vpn_state = nm_vpn_connection_get_vpn_state (NM_VPN_CONNECTION (acon));
			vpn_state_str = g_strdup_printf ("%d - %s", vpn_state, vpn_connection_state_to_string (vpn_state));

			/* Add values */
			arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
			set_val_strc (arr, 0, nmc_fields_con_active_details_groups[5].name);
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

	g_array_free (print_groups, TRUE);
	if (group_fields)
		g_ptr_array_free (group_fields, TRUE);

	return TRUE;
}

static gboolean
split_required_fields_for_con_show (const char *input,
                                    char **profile_flds,
                                    char **active_flds,
                                    GError **error)
{
	char **fields, **iter;
	char *dot;
	GString *str1, *str2;
	gboolean found;
	gboolean group_profile = FALSE;
	gboolean group_active = FALSE;
	gboolean success = TRUE;
	gboolean is_all, is_common;
	int i;

	if (!input) {
		*profile_flds = NULL;
		*active_flds = NULL;
		return TRUE;
	}

	str1 = g_string_new (NULL);
	str2 = g_string_new (NULL);

	/* Split supplied fields string */
	fields = g_strsplit_set (input, ",", -1);
	for (iter = fields; iter && *iter; iter++) {
		g_strstrip (*iter);
		dot = strchr (*iter, '.');
		if (dot)
			*dot = '\0';

		is_all = !dot && strcasecmp (*iter, "all") == 0;
		is_common = !dot && strcasecmp (*iter, "common") == 0;

		found = FALSE;

		for (i = 0; nmc_fields_settings_names[i].name; i++) {
			if (   is_all || is_common
			    || !strcasecmp (*iter, nmc_fields_settings_names[i].name)) {
				if (dot)
					*dot = '.';
				g_string_append (str1, *iter);
				g_string_append_c (str1, ',');
				found = TRUE;
				break;
			}
		}
		if (found)
			continue;
		for (i = 0; nmc_fields_con_active_details_groups[i].name; i++) {
			if (   is_all || is_common
			    || !strcasecmp (*iter, nmc_fields_con_active_details_groups[i].name)) {
				if (dot)
					*dot = '.';
				g_string_append (str2, *iter);
				g_string_append_c (str2, ',');
				found = TRUE;
				break;
			}
		}
		if (!found) {
			if (dot)
				*dot = '.';
			if (!strcasecmp (*iter, CON_SHOW_DETAIL_GROUP_PROFILE))
				group_profile = TRUE;
			else if (!strcasecmp (*iter, CON_SHOW_DETAIL_GROUP_ACTIVE))
				group_active = TRUE;
			else {
				char *allowed1 = nmc_get_allowed_fields (nmc_fields_settings_names, -1);
				char *allowed2 = nmc_get_allowed_fields (nmc_fields_con_active_details_groups, -1);
				g_set_error (error, NMCLI_ERROR, 0, _("invalid field '%s'; allowed fields: %s and %s, or %s,%s"),
				             *iter, allowed1, allowed2, CON_SHOW_DETAIL_GROUP_PROFILE, CON_SHOW_DETAIL_GROUP_ACTIVE);
				g_free (allowed1);
				g_free (allowed2);
				success = FALSE;
				break;
			}
		}
	}
	if (fields)
		g_strfreev (fields);

	/* Handle pseudo groups: profile, active */
	if (success && group_profile) {
		if (str1->len > 0) {
			g_set_error (error, NMCLI_ERROR, 0, _("'%s' has to be alone"),
			             CON_SHOW_DETAIL_GROUP_PROFILE);
			success = FALSE;
		} else
			g_string_assign (str1, "all,");
	}
	if (success && group_active) {
		if (str2->len > 0) {
			g_set_error (error, NMCLI_ERROR, 0, _("'%s' has to be alone"),
			             CON_SHOW_DETAIL_GROUP_ACTIVE);
			success = FALSE;
		} else
			g_string_assign (str2, "all,");
	}

	if (success) {
		if (str1->len > 0)
			g_string_truncate (str1, str1->len - 1);
		if (str2->len > 0)
			g_string_truncate (str2, str2->len - 1);
		*profile_flds = g_string_free (str1, str1->len == 0);
		*active_flds = g_string_free (str2, str2->len == 0);
	} else {
		g_string_free (str1, TRUE);
		g_string_free (str2, TRUE);
	}
	return success;
}

typedef enum {
	NMC_SORT_ACTIVE     =  1,
	NMC_SORT_ACTIVE_INV = -1,
	NMC_SORT_NAME       =  2,
	NMC_SORT_NAME_INV   = -2,
	NMC_SORT_TYPE       =  3,
	NMC_SORT_TYPE_INV   = -3,
	NMC_SORT_PATH       =  4,
	NMC_SORT_PATH_INV   = -4,
} NmcSortOrder;

typedef struct {
	NmCli *nmc;
	const GArray *order;
} NmcSortInfo;

static int
compare_connections (gconstpointer a, gconstpointer b, gpointer user_data)
{
	NMConnection *ca = *(NMConnection **)a;
	NMConnection *cb = *(NMConnection **)b;
	NMActiveConnection *aca, *acb;
	NmcSortInfo *info = (NmcSortInfo *) user_data;
	GArray *default_order = NULL;
	const GArray *order;
	NmcSortOrder item;
	int cmp = 0, i;
	const char *tmp1, *tmp2;
	unsigned long tmp1_int, tmp2_int;

	if (info->order )
		order = info->order;
	else {
		NmcSortOrder def[] = { NMC_SORT_ACTIVE, NMC_SORT_NAME, NMC_SORT_PATH };
		int num = G_N_ELEMENTS (def);
		default_order = g_array_sized_new (FALSE, FALSE, sizeof (NmcSortOrder), num);
		g_array_append_vals (default_order, def, num);
		order = default_order;
	}

	for (i = 0; i < order->len; i++) {
		item = g_array_index (order, NmcSortOrder, i); 
		switch (item) {
		case NMC_SORT_ACTIVE:
		case NMC_SORT_ACTIVE_INV:
			aca = get_ac_for_connection (nm_client_get_active_connections (info->nmc->client), ca);
			acb = get_ac_for_connection (nm_client_get_active_connections (info->nmc->client), cb);
			cmp = (aca && !acb) ? -1 : (!aca && acb) ? 1 : 0;
			if (item == NMC_SORT_ACTIVE_INV)
				cmp = -(cmp);
			break;
		case NMC_SORT_TYPE:
		case NMC_SORT_TYPE_INV:
			cmp = g_strcmp0 (nm_connection_get_connection_type (ca),
			                 nm_connection_get_connection_type (cb));
			if (item == NMC_SORT_TYPE_INV)
				cmp = -(cmp);
			break;
		case NMC_SORT_NAME:
		case NMC_SORT_NAME_INV:
			cmp = g_strcmp0 (nm_connection_get_id (ca),
			                 nm_connection_get_id (cb));
			if (item == NMC_SORT_NAME_INV)
				cmp = -(cmp);
			break;
		case NMC_SORT_PATH:
		case NMC_SORT_PATH_INV:
			tmp1 = nm_connection_get_path (ca);
			tmp2 = nm_connection_get_path (cb);
			tmp1 = tmp1 ? strrchr (tmp1, '/') : "0";
			tmp2 = tmp2 ? strrchr (tmp2, '/') : "0";
			nmc_string_to_uint (tmp1 ? tmp1+1 : "0", FALSE, 0, 0, &tmp1_int);
			nmc_string_to_uint (tmp2 ? tmp2+1 : "0", FALSE, 0, 0, &tmp2_int);
			cmp = (int) tmp1_int - tmp2_int;
			if (item == NMC_SORT_PATH_INV)
				cmp = -(cmp);
			break;
		default:
			cmp = 0;
			break;
		}
		if (cmp != 0)
			goto end;
	}
end:
	if (default_order)
		g_array_unref (default_order);
	return cmp;
}

static GPtrArray *
sort_connections (const GPtrArray *cons, NmCli *nmc, const GArray *order)
{
	GPtrArray *sorted;
	int i;
	NmcSortInfo compare_info;

	compare_info.nmc = nmc;
	compare_info.order = order;

	sorted = g_ptr_array_sized_new (cons->len);
	for (i = 0; cons && i < cons->len; i++)
		g_ptr_array_add (sorted, cons->pdata[i]);
	g_ptr_array_sort_with_data (sorted, compare_connections, &compare_info);
	return sorted;
}

static int
compare_ac_connections (gconstpointer a, gconstpointer b, gpointer user_data)
{
	NMActiveConnection *ca = *(NMActiveConnection **)a;
	NMActiveConnection *cb = *(NMActiveConnection **)b;
	int cmp;

	/* Sort states first */
	cmp = nm_active_connection_get_state (cb) - nm_active_connection_get_state (ca);
	if (cmp != 0)
		return cmp;

	cmp = g_strcmp0 (nm_active_connection_get_id (ca),
	                 nm_active_connection_get_id (cb));
	if (cmp != 0)
		return cmp;

	return g_strcmp0 (nm_active_connection_get_connection_type (ca),
	                  nm_active_connection_get_connection_type (cb));
}

static GPtrArray *
get_invisible_active_connections (NmCli *nmc)
{
	const GPtrArray *acons;
	GPtrArray *invisibles;
	int a, c;

	g_return_val_if_fail (nmc != NULL, NULL);

	invisibles = g_ptr_array_new ();
	acons = nm_client_get_active_connections (nmc->client);
	for (a = 0; a < acons->len; a++) {
		gboolean found = FALSE;
		NMActiveConnection *acon = g_ptr_array_index (acons, a);
		const char *a_uuid = nm_active_connection_get_uuid (acon);

		for (c = 0; c < nmc->connections->len; c++) {
			NMConnection *con = g_ptr_array_index (nmc->connections, c);
			const char *c_uuid = nm_connection_get_uuid (con);

			if (strcmp (a_uuid, c_uuid) == 0) {
				found = TRUE;
				break;
			}
		}
		/* Active connection is not in connections array, add it to  */
		if (!found)
			g_ptr_array_add (invisibles, acon);
	}
	g_ptr_array_sort_with_data (invisibles, compare_ac_connections, NULL);
	return invisibles;
}

static NMCResultCode
do_connections_show (NmCli *nmc, gboolean active_only, gboolean show_secrets,
                     const GArray *order, int argc, char **argv)
{
	GError *err = NULL;
	char *profile_flds = NULL, *active_flds = NULL;
	GPtrArray *invisibles, *sorted_cons;

	nmc->should_wait = FALSE;

	if (argc == 0) {
		char *fields_str;
		char *fields_all =    NMC_FIELDS_CON_SHOW_ALL;
		char *fields_common = NMC_FIELDS_CON_SHOW_COMMON;
		NmcOutputField *tmpl, *arr;
		size_t tmpl_len;
		int i;

		if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
			fields_str = fields_common;
		else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
			fields_str = fields_all;
		else
			fields_str = nmc->required_fields;

		tmpl = nmc_fields_con_show;
		tmpl_len = sizeof (nmc_fields_con_show);
		nmc->print_fields.indices = parse_output_fields (fields_str, tmpl, FALSE, NULL, &err);
		if (err) {
			goto finish;
		}
		if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &err))
			goto finish;

		/* Add headers */
		nmc->print_fields.header_name = active_only ? _("NetworkManager active profiles") :
		                                              _("NetworkManager connection profiles");
		arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
		g_ptr_array_add (nmc->output_data, arr);

		/* There might be active connections not present in connection list
		 * (e.g. private connections of a different user). Show them as well. */
		invisibles = get_invisible_active_connections (nmc);
		for (i = 0; i < invisibles->len; i++)
			fill_output_connection_for_invisible (invisibles->pdata[i], nmc);
		g_ptr_array_free (invisibles, FALSE);

		/* Sort the connections and fill the output data */
		sorted_cons = sort_connections (nmc->connections, nmc, order);
		for (i = 0; i < sorted_cons->len; i++)
			fill_output_connection (sorted_cons->pdata[i], nmc, active_only);
		g_ptr_array_free (sorted_cons, FALSE);

		print_data (nmc);  /* Print all data */
	} else {
		gboolean new_line = FALSE;
		gboolean without_fields = (nmc->required_fields == NULL);
		const GPtrArray *active_cons = nm_client_get_active_connections (nmc->client);
		int pos = 0;

		/* multiline mode is default for 'connection show <ID>' */
		if (!nmc->mode_specified)
			nmc->multiline_output = TRUE;

		/* Split required fields into the settings and active ones. */
		if (!split_required_fields_for_con_show (nmc->required_fields, &profile_flds, &active_flds, &err))
			goto finish;
		g_free (nmc->required_fields);
		nmc->required_fields = NULL;

		while (argc > 0) {
			gboolean res;
			NMConnection *con;
			NMActiveConnection *acon = NULL;
			const char *selector = NULL;

			if (   strcmp (*argv, "id") == 0
			    || strcmp (*argv, "uuid") == 0
			    || strcmp (*argv, "path") == 0
			    || strcmp (*argv, "apath") == 0) {
				selector = *argv;
				if (next_arg (&argc, &argv) != 0) {
					g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					goto finish;
				}
			}

			/* Find connection by id, uuid, path or apath */
			con = nmc_find_connection (nmc->connections, selector, *argv, &pos);
			if (!con) {
				acon = find_active_connection (active_cons, nmc->connections, selector, *argv, NULL);
				if (acon)
					con = NM_CONNECTION (nm_active_connection_get_connection (acon));
			}
			
			if (!con && !acon) {
				g_string_printf (nmc->return_text, _("Error: %s - no such connection profile."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
				goto finish;
			}

			/* Print connection details:
			 * Usually we have both static and active connection.
			 * But when a connection is private to a user, another user
			 * may see only the active connection.
			 */

			/* Filter only active connections */
			if (!acon)
				acon = get_ac_for_connection (active_cons, con);
			if (active_only && !acon) {
				next_arg (&argc, &argv);
				continue;
			}

			/* Show an empty line between connections */
			if (new_line)
				g_print ("\n");

			/* Show profile configuration */
			if (without_fields || profile_flds) {
				if (con) {
					nmc->required_fields = profile_flds;
					if (show_secrets)
						update_secrets_in_connection (NM_REMOTE_CONNECTION (con), con);
					res = nmc_connection_profile_details (con, nmc, show_secrets);
					nmc->required_fields = NULL;
					if (!res)
						goto finish;
				}
			}

			/* If the profile is active, print also active details */
			if (without_fields || active_flds) {
				if (acon) {
					nmc->required_fields = active_flds;
					res = nmc_active_connection_details (acon, nmc);
					nmc->required_fields = NULL;
					if (!res)
						goto finish;
				}
			}
			new_line = TRUE;
			
			/* Take next argument.
			 * But for pos != NULL we have more connections of the same name,
			 * so process the same argument again.
			 */
			if (!pos)
				next_arg (&argc, &argv);
		}
	}

finish:
	if (err) {
		g_string_printf (nmc->return_text, _("Error: %s."), err->message);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		g_error_free (err);
	}
	g_free (profile_flds);
	g_free (active_flds);
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
	for (i = 0; i < connections->len; i++) {
		NMActiveConnection *candidate = g_ptr_array_index (connections, i);
		const GPtrArray *devices;

		devices = nm_active_connection_get_devices (candidate);
		if (!devices->len)
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
	g_return_val_if_fail (iface || ap || nsp, FALSE);
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

		for (i = 0; i < devices->len && !found_device; i++) {
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

				for (j = 0; j < aps->len; j++) {
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
vpn_connection_state_reason_to_string (NMVpnConnectionStateReason reason)
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
device_state_cb (NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;
	NMActiveConnection *active;
	NMDeviceState state;
	NMActiveConnectionState ac_state;

	active = nm_device_get_active_connection (device);
	state = nm_device_get_state (device);

	ac_state = active ? nm_active_connection_get_state (active) : NM_ACTIVE_CONNECTION_STATE_UNKNOWN;

	if (ac_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
		if (nmc->print_output == NMC_PRINT_PRETTY)
			nmc_terminal_erase_line ();
		g_print (_("Connection successfully activated (D-Bus active path: %s)\n"),
		         nm_object_get_path (NM_OBJECT (active)));
		quit ();
	} else if (   ac_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATING
	           && state == NM_DEVICE_STATE_IP_CONFIG) {
		if (nmc->print_output == NMC_PRINT_PRETTY)
			nmc_terminal_erase_line ();
		g_print (_("Connection successfully activated (master waiting for slaves) (D-Bus active path: %s)\n"),
		         nm_object_get_path (NM_OBJECT (active)));
		quit ();
	} else if (active && ac_state != NM_ACTIVE_CONNECTION_STATE_ACTIVATING) {
		g_string_printf (nmc->return_text, _("Error: Connection activation failed."));
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		quit ();
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
		g_print (_("Connection successfully activated (D-Bus active path: %s)\n"),
		         nm_object_get_path (NM_OBJECT (active)));
		g_object_unref (active);
		quit ();
	} else if (state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED) {
		g_string_printf (nmc->return_text, _("Error: Connection activation failed."));
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		g_object_unref (active);
		quit ();
	} else if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATING) {
		/* activating master connection does not automatically activate any slaves, so their
		 * active connection state will not progress beyond ACTIVATING state.
		 * Monitor the device instead. */
		const GPtrArray *devices;
		NMDevice *device;

		if (nmc->secret_agent) {
			NMRemoteConnection *connection = nm_active_connection_get_connection (active);

			nm_secret_agent_simple_enable (NM_SECRET_AGENT_SIMPLE (nmc->secret_agent),
			                               nm_connection_get_path (NM_CONNECTION (connection)));
		}

		devices = nm_active_connection_get_devices (active);
		device = devices->len ? g_ptr_array_index (devices, 0) : NULL;
		if (   device
		    && (   NM_IS_DEVICE_BOND (device)
		        || NM_IS_DEVICE_TEAM (device)
		        || NM_IS_DEVICE_BRIDGE (device))) {
			g_signal_handlers_disconnect_by_func (active, G_CALLBACK (active_connection_state_cb), nmc);
			g_signal_connect (device, "notify::" NM_DEVICE_STATE, G_CALLBACK (device_state_cb), nmc);

			device_state_cb (device, NULL, nmc);
		}
	}
}

static void
vpn_connection_state_cb (NMVpnConnection *vpn,
                         NMVpnConnectionState state,
                         NMVpnConnectionStateReason reason,
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
		g_print (_("VPN connection successfully activated (D-Bus active path: %s)\n"),
		         nm_object_get_path (NM_OBJECT (vpn)));
		g_object_unref (vpn);
		quit ();
		break;

	case NM_VPN_CONNECTION_STATE_FAILED:
	case NM_VPN_CONNECTION_STATE_DISCONNECTED:
		g_string_printf (nmc->return_text, _("Error: Connection activation failed: %s."),
		                 vpn_connection_state_reason_to_string (reason));
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		g_object_unref (vpn);
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
	NMVpnConnection *vpn = (NMVpnConnection *) user_data;
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

static void
activate_connection_cb (GObject *client, GAsyncResult *result, gpointer user_data)
{
	ActivateConnectionInfo *info = (ActivateConnectionInfo *) user_data;
	NmCli *nmc = info->nmc;
	NMDevice *device = info->device;
	NMActiveConnection *active;
	NMActiveConnectionState state;
	const GPtrArray *ac_devs;
	GError *error = NULL;

	active = nm_client_activate_connection_finish (NM_CLIENT (client), result, &error);

	if (error) {
		g_string_printf (nmc->return_text, _("Error: Connection activation failed: %s"),
		                 error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		quit ();
	} else {
		state = nm_active_connection_get_state (active);
		if (!device) {
			/* device could be NULL for virtual devices. Fill it here. */
			ac_devs = nm_active_connection_get_devices (active);
			info->device = device = ac_devs->len > 0 ? g_ptr_array_index (ac_devs, 0) : NULL;
		}

		if (nmc->nowait_flag || state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
			/* User doesn't want to wait or already activated */
			if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
				if (nmc->print_output == NMC_PRINT_PRETTY)
					nmc_terminal_erase_line ();
				g_print (_("Connection successfully activated (D-Bus active path: %s)\n"),
				         nm_object_get_path (NM_OBJECT (active)));
			}
			g_object_unref (active);
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
				active_connection_state_cb (active, NULL, nmc);

				/* Start progress indication showing device states */
				if (nmc->print_output == NMC_PRINT_PRETTY) {
					if (progress_id)
						g_source_remove (progress_id);
					progress_id = g_timeout_add (120, progress_device_cb, device);
				}
			}

			/* Start timer not to loop forever when signals are not emitted */
			g_timeout_add_seconds (nmc->timeout, timeout_cb, nmc);
		}
	}
	g_free (info);
}

/**
 * parse_passwords:
 * @passwd_file: file with passwords to parse
 * @error: location to store error, or %NULL
 *
 * Parse passwords given in @passwd_file and insert them into a hash table.
 * Example of @passwd_file contents:
 *   wifi.psk:tajne heslo
 *   802-1x.password:krakonos
 *   802-11-wireless-security:leap-password:my leap password
 *
 * Returns: hash table with parsed passwords, or %NULL on an error
 */
static GHashTable *
parse_passwords (const char *passwd_file, GError **error)
{
	GHashTable *pwds_hash;
	char *contents = NULL;
	gsize len = 0;
	GError *local_err = NULL;
	char **lines, **iter;
	char *pwd_spec, *pwd, *prop;
	const char *setting;

	pwds_hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	if (!passwd_file)
		return pwds_hash;

        /* Read the passwords file */
	if (!g_file_get_contents (passwd_file, &contents, &len, &local_err)) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("failed to read passwd-file '%s': %s"),
		             passwd_file, local_err->message);
		g_error_free (local_err);
		g_hash_table_destroy (pwds_hash);
		return NULL;
	}

	lines = nmc_strsplit_set (contents, "\r\n", -1);
	for (iter = lines; *iter; iter++) {
		pwd = strchr (*iter, ':');
		if (!pwd) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("missing colon in 'password' entry '%s'"), *iter);
			goto failure;
		}
		*(pwd++) = '\0';

		prop = strchr (*iter, '.');
		if (!prop) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("missing dot in 'password' entry '%s'"), *iter);
			goto failure;
		}
		*(prop++) = '\0';

		setting = *iter;
		while (g_ascii_isspace (*setting))
			setting++;
		/* Accept wifi-sec or wifi instead of cumbersome '802-11-wireless-security' */
		if (!strcmp (setting, "wifi-sec") || !strcmp (setting, "wifi"))
			setting = NM_SETTING_WIRELESS_SECURITY_SETTING_NAME;
		if (nm_setting_lookup_type (setting) == G_TYPE_INVALID) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("invalid setting name in 'password' entry '%s'"), setting);
			goto failure;
		}

		pwd_spec = g_strdup_printf ("%s.%s", setting, prop);
		g_hash_table_insert (pwds_hash, pwd_spec, g_strdup (pwd));
	}
	g_strfreev (lines);
	g_free (contents);
	return pwds_hash;

failure:
	g_strfreev (lines);
	g_free (contents);
	g_hash_table_destroy (pwds_hash);
	return NULL;
}



static gboolean
nmc_activate_connection (NmCli *nmc,
                         NMConnection *connection,
                         const char *ifname,
                         const char *ap,
                         const char *nsp,
                         const char *pwds,
                         GAsyncReadyCallback callback,
                         GError **error)
{
	ActivateConnectionInfo *info;

	GHashTable *pwds_hash;
	NMDevice *device = NULL;
	const char *spec_object = NULL;
	gboolean device_found;
	GError *local = NULL;

	g_return_val_if_fail (nmc != NULL, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (connection && (ifname || ap || nsp)) {
		device_found = find_device_for_connection (nmc, connection, ifname, ap, nsp, &device, &spec_object, &local);

		/* Virtual connection may not have their interfaces created yet */
		if (!device_found && !nm_connection_is_virtual (connection)) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_CON_ACTIVATION,
				     "%s", local && local->message ? local->message : _("unknown error"));
			g_clear_error (&local);
			return FALSE;
		}
		g_clear_error (&local);
	} else if (ifname) {
		device = nm_client_get_device_by_iface (nmc->client, ifname);
		if (!device) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_NOT_FOUND,
			             _("unknown device '%s'."), ifname);
			return FALSE;
		}
	} else if (!connection) {
		g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_NOT_FOUND,
		                     _("neither a valid connection nor device given"));
		return FALSE;
	}

	/* Parse passwords given in passwords file */
	pwds_hash = parse_passwords (pwds, &local);
	if (local) {
		g_propagate_error (error, local);
		return FALSE;
	}
	if (nmc->pwds_hash)
		g_hash_table_destroy (nmc->pwds_hash);
	nmc->pwds_hash = pwds_hash;

	/* Create secret agent */
	nmc->secret_agent = nm_secret_agent_simple_new ("nmcli-connect");
	if (nmc->secret_agent) {
		g_signal_connect (nmc->secret_agent, "request-secrets", G_CALLBACK (nmc_secrets_requested), nmc);
		if (connection) {
			nm_secret_agent_simple_enable (NM_SECRET_AGENT_SIMPLE (nmc->secret_agent),
			                               nm_object_get_path (NM_OBJECT (connection)));
		}
	}

	info = g_malloc0 (sizeof (ActivateConnectionInfo));
	info->nmc = nmc;
	info->device = device;

	nm_client_activate_connection_async (nmc->client,
	                                     connection,
	                                     device,
	                                     spec_object,
	                                     NULL,
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
	const char *pwds = NULL;
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
			line = nmc_readline (PROMPT_CONNECTION);
			name = line ? line : "";
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

	if (name) {
		connection = nmc_find_connection (nmc->connections, selector, name, NULL);
		if (!connection) {
			g_string_printf (nmc->return_text, _("Error: Connection '%s' does not exist."), name);
			nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
			goto error;
		}
	}

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
		else if (strcmp (*argv, "passwd-file") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}

			pwds = *argv;
		}
		else {
			g_printerr (_("Unknown parameter: %s\n"), *argv);
		}

		argc--;
		argv++;
	}

	/* Use nowait_flag instead of should_wait because exiting has to be postponed till
	 * active_connection_state_cb() is called. That gives NM time to check our permissions
	 * and we can follow activation progress.
	 */
	nmc->nowait_flag = (nmc->timeout == 0);
	nmc->should_wait = TRUE;

	if (!nmc_activate_connection (nmc, connection, ifname, ap, nsp, pwds, activate_connection_cb, &error)) {
		g_string_printf (nmc->return_text, _("Error: %s."),
		                 error ? error->message : _("unknown error"));
		nmc->return_value = error ? error->code : NMC_RESULT_ERROR_CON_ACTIVATION;
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

typedef struct {
	NmCli *nmc;
	GSList *queue;
	guint timeout_id;
} ConnectionCbInfo;

static void connection_cb_info_finish (ConnectionCbInfo *info,
                                       gpointer connection);

static void
connection_removed_cb (NMClient *client, NMConnection *connection, ConnectionCbInfo *info)
{
	if (!g_slist_find (info->queue, connection))
		return;
	g_print (_("Connection '%s' (%s) successfully deleted.\n"),
	         nm_connection_get_id (connection),
	         nm_connection_get_uuid (connection));
	connection_cb_info_finish (info, connection);
}

static void
down_active_connection_state_cb (NMActiveConnection *active,
                                 GParamSpec *pspec,
                                 ConnectionCbInfo *info)
{
	if (nm_active_connection_get_state (active) < NM_ACTIVE_CONNECTION_STATE_DEACTIVATED)
		return;

	if (info->nmc->print_output == NMC_PRINT_PRETTY)
		nmc_terminal_erase_line ();
	g_print (_("Connection '%s' successfully deactivated (D-Bus active path: %s)\n"),
	         nm_active_connection_get_id (active), nm_object_get_path (NM_OBJECT (active)));

	g_signal_handlers_disconnect_by_func (G_OBJECT (active),
	                                      down_active_connection_state_cb,
	                                      info);
	connection_cb_info_finish (info, active);
}

static gboolean
connection_op_timeout_cb (gpointer user_data)
{
	ConnectionCbInfo *info = user_data;

	timeout_cb (info->nmc);
	connection_cb_info_finish (info, NULL);
	return G_SOURCE_REMOVE;
}

static void
destroy_queue_element (gpointer data)
{
	g_signal_handlers_disconnect_matched (data, G_SIGNAL_MATCH_FUNC, 0, 0, 0,
	                                      down_active_connection_state_cb, NULL);
	g_object_unref (data);
}

static void
connection_cb_info_finish (ConnectionCbInfo *info, gpointer connection)
{
	if (connection) {
		info->queue = g_slist_remove (info->queue, connection);
		g_object_unref (G_OBJECT (connection));
	} else {
		g_slist_free_full (info->queue, destroy_queue_element);
		info->queue = NULL;
	}

	if (info->queue)
		return;

	if (info->timeout_id)
		g_source_remove (info->timeout_id);
	g_signal_handlers_disconnect_by_func (info->nmc->client, connection_removed_cb, info);
	g_slice_free (ConnectionCbInfo, info);
	quit ();
}

static NMCResultCode
do_connection_down (NmCli *nmc, int argc, char **argv)
{
	NMActiveConnection *active;
	ConnectionCbInfo *info = NULL;
	const GPtrArray *active_cons;
	GSList *queue = NULL, *iter;
	char **arg_arr = NULL;
	char **arg_ptr = argv;
	int arg_num = argc;
	int idx = 0;

	if (nmc->timeout == -1)
		nmc->timeout = 10;

	if (argc == 0) {
		if (nmc->ask) {
			char *line = nmc_readline (PROMPT_ACTIVE_CONNECTIONS);
			nmc_string_to_arg_array (line, NULL, TRUE, &arg_arr, &arg_num);
			g_free (line);
			arg_ptr = arg_arr;
		}
		if (arg_num == 0) {
			g_string_printf (nmc->return_text, _("Error: No connection specified."));
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto error;
		}
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

		active = find_active_connection (active_cons, nmc->connections, selector, *arg_ptr, &idx);
		if (active) {
			/* Check if the connection is unique. */
			/* Calling down for the same connection repeatedly would result in
			 * NM responding for the last D-Bus call only and we would stall. */
			if (!g_slist_find (queue, active))
				queue = g_slist_prepend (queue, g_object_ref (active));
		} else {
			g_printerr (_("Error: '%s' is not an active connection.\n"), *arg_ptr);
			g_string_printf (nmc->return_text, _("Error: not all active connections found."));
			nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
		}

		if (idx == 0)
			next_arg (&arg_num, &arg_ptr);
	}

	if (!queue) {
		g_string_printf (nmc->return_text, _("Error: no active connection provided."));
		nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
		goto error;
	}
	queue = g_slist_reverse (queue);

	if (nmc->timeout > 0) {
		nmc->should_wait = TRUE;

		info = g_slice_new0 (ConnectionCbInfo);
		info->nmc = nmc;
		info->queue = queue;
		info->timeout_id = g_timeout_add_seconds (nmc->timeout, connection_op_timeout_cb, info);
	}

	for (iter = queue; iter; iter = g_slist_next (iter)) {
		active = iter->data;

		if (info)
			g_signal_connect (active,
			                  "notify::" NM_ACTIVE_CONNECTION_STATE,
			                  G_CALLBACK (down_active_connection_state_cb),
			                  info);

		/* Now deactivate the connection */
		nm_client_deactivate_connection (nmc->client, active, NULL, NULL);
	}

error:
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

static const NameItem nmc_generic_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_ethernet_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet", NULL, TRUE  },
	{ NM_SETTING_802_1X_SETTING_NAME,     NULL,       NULL, FALSE },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME, NULL,       NULL, FALSE },
	{ NM_SETTING_DCB_SETTING_NAME,        NULL,       NULL, FALSE },
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

/* PPPoE is a base connection type from historical reasons.
 * See libnm-core/nm-setting.c:_nm_setting_is_base_type()
 */
static const NameItem nmc_pppoe_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet", NULL, TRUE  },
	{ NM_SETTING_PPPOE_SETTING_NAME,      NULL,       NULL, TRUE  },
	{ NM_SETTING_PPP_SETTING_NAME,        NULL,       NULL, FALSE },
	{ NM_SETTING_802_1X_SETTING_NAME,     NULL,       NULL, FALSE },
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
	{ NM_SETTING_GENERIC_SETTING_NAME,    NULL,        nmc_generic_settings      },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet",  nmc_ethernet_settings     },
	{ NM_SETTING_PPPOE_SETTING_NAME,      NULL,        nmc_pppoe_settings        },
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
		if (!g_strcmp0 (con_type, nmc_valid_connection_types[i].name))
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
check_mac (const char *mac,
           int type,
           const char *keyword,
           GError **error)
{
	g_return_val_if_fail (type == ARPHRD_ETHER || type == ARPHRD_INFINIBAND, FALSE);

	if (!mac)
		return TRUE;

	if (!nm_utils_hwaddr_valid (mac, nm_utils_hwaddr_len (type))) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: '%s': '%s' is not a valid %s MAC address."),
		             keyword, mac, type == ARPHRD_INFINIBAND ? _("InfiniBand") : _("Ethernet"));
		return FALSE;
	}

	return TRUE;
}

static gboolean
check_and_convert_mtu (const char *mtu, guint32 *mtu_int, GError **error)
{
	unsigned long local_mtu_int;

	if (mtu_int)
		*mtu_int = 0;

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

/**
 * check_valid_enumeration:
 * @str: string to check against string array @strings
 * @strings: string array to check @str againt
 * @what: what parameter @str belongs to (used in error message)
 * @what_desc: longer description of @what parameter (used in error message)
 * @error: location to store an error, or %NULL
 *
 * Check whether @str is one of the string of @strings array. It accepts
 * shortcuts and normalizes them (@str argument is modified on success).
 *
 * Returns: %TRUE on success, %FALSE on failure
 */
static gboolean
check_valid_enumeration (char **str,
                         const char *strings[],
                         const char *what,
                         const char *what_desc,
                         GError **error)
{
	char *tmp;
	const char *checked_str;

	if (!str || !*str)
		return TRUE;

	tmp = g_strstrip (g_strdup (*str));
	checked_str = nmc_string_is_valid (tmp, strings, NULL);
	g_free (tmp);
	if (checked_str) {
		g_free (*str);
		*str = g_strdup (checked_str);
	} else {
		char *options;

		options = nmc_util_strv_for_display (strings, TRUE);
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: '%s': '%s' is not a valid %s %s."),
		             what, *str, what_desc, options);
		g_free (options);
	}
	return !!checked_str;
}

/* Checks Wi-Fi mode. */
static gboolean
check_wifi_mode (char **mode, GError **error)
{
	const char *modes[] = { "infrastructure", "ap", "adhoc", NULL };

	return check_valid_enumeration (mode, modes, "mode", _("Wi-Fi mode"), error);
}

/* Checks InfiniBand mode. */
static gboolean
check_infiniband_mode (char **mode, GError **error)
{
	const char *modes[] = { "datagram", "connected", NULL };

	return check_valid_enumeration (mode, modes, "mode", _("InfiniBand transport mode"), error);
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
add_ip4_address_to_connection (NMIPAddress *ip4addr, NMConnection *connection)
{
	NMSettingIPConfig *s_ip4;
	gboolean ret;

	if (!ip4addr)
		return TRUE;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (!s_ip4) {
		s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_ip4));
		g_object_set (s_ip4,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
		              NULL);
	}
	ret = nm_setting_ip_config_add_address (s_ip4, ip4addr);
	nm_ip_address_unref (ip4addr);

	return ret;
}

static gboolean
add_ip6_address_to_connection (NMIPAddress *ip6addr, NMConnection *connection)
{
	NMSettingIPConfig *s_ip6;
	gboolean ret;

	if (!ip6addr)
		return TRUE;

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (!s_ip6) {
		s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_ip6));
		g_object_set (s_ip6,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
		              NULL);
	}
	ret = nm_setting_ip_config_add_address (s_ip6, ip6addr);
	nm_ip_address_unref (ip6addr);

	return ret;
}

static char *
unique_master_iface_ifname (const GPtrArray *connections,
                            const char *try_name)
{
	NMConnection *connection;
	char *new_name;
	unsigned int num = 1;
	int i = 0;
	const char *ifname = NULL;

	new_name = g_strdup (try_name);
	while (i < connections->len) {
		connection = NM_CONNECTION (connections->pdata[i]);
		ifname = nm_connection_get_interface_name (connection);
		if (g_strcmp0 (new_name, ifname) == 0) {
			g_free (new_name);
			new_name = g_strdup_printf ("%s%d", try_name, num++);
			i = 0;
		} else
			i++;
	}
	return new_name;
}

static const char *
_strip_master_prefix (const char *master, const char *(**func)(NMConnection *))
{
	if (!master)
		return NULL;

	if (g_str_has_prefix (master, "ifname/")) {
		master = master + strlen ("ifname/");
		if (func)
			*func = nm_connection_get_interface_name;
	} else if (g_str_has_prefix (master, "uuid/")) {
		master = master + strlen ("uuid/");
		if (func)
			*func = nm_connection_get_uuid;
	} else if (g_str_has_prefix (master, "id/")) {
		master = master + strlen ("id/");
		if (func)
			 *func = nm_connection_get_id;
	}
	return master;
}

/* verify_master_for_slave:
 * @connections: list af all connections
 * @master: UUID, ifname or ID of the master connection
 * @type: virtual connection type (bond, team, bridge, ...)
 *
 * Check whether master is a valid interface name, UUID or ID of some @type connection.
 * First UUID and ifname are checked. If they don't match, ID is checked
 * and replaced by UUID on a match.
 *
 * Returns: identifier of master connection if found, %NULL otherwise
 */
static const char *
verify_master_for_slave (const GPtrArray *connections,
                         const char *master,
                         const char *type)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	const char *con_type, *id, *uuid, *ifname;
	int i;
	const char *found_by_id = NULL;
	const char *out_master = NULL;
	const char *(*func) (NMConnection *) = NULL;

	if (!master)
		return NULL;

	master = _strip_master_prefix (master, &func);
	for (i = 0; i < connections->len; i++) {
		connection = NM_CONNECTION (connections->pdata[i]);
		s_con = nm_connection_get_setting_connection (connection);
		g_assert (s_con);
		con_type = nm_setting_connection_get_connection_type (s_con);
		if (g_strcmp0 (con_type, type) != 0)
			continue;
		if (func) {
			/* There was a prefix; only compare to that type. */
			if (g_strcmp0 (master, func (connection)) == 0) {
				if (func == nm_connection_get_id)
					out_master = nm_connection_get_uuid (connection);
				else
					out_master = master;
				break;
			}
		} else {
			id = nm_connection_get_id (connection);
			uuid = nm_connection_get_uuid (connection);
			ifname = nm_connection_get_interface_name (connection);
			if (   g_strcmp0 (master, uuid) == 0
			    || g_strcmp0 (master, ifname) == 0) {
				out_master = master;
				break;
			}
			if (!found_by_id && g_strcmp0 (master, id) == 0)
				found_by_id = uuid;
		}
	}
	return out_master ? out_master : found_by_id;
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

#define WORD_YES "yes"
#define WORD_NO  "no"
#define WORD_LOC_YES _("yes")
#define WORD_LOC_NO  _("no")
static const char *
prompt_yes_no (gboolean default_yes, char *delim)
{
	static char prompt[128] = { 0 };

	if (!delim)
		delim = "";

	snprintf (prompt, sizeof (prompt), "(%s/%s) [%s]%s ",
	          WORD_LOC_YES, WORD_LOC_NO,
	          default_yes ? WORD_LOC_YES : WORD_LOC_NO, delim);

	return prompt;
}

static gboolean
normalize_yes_no (char **yes_no)
{
	char *tmp;
	const char *checked_yes_no;
	const char *strv[] = { WORD_LOC_YES, WORD_LOC_NO, NULL };

	if (!yes_no || !*yes_no)
		return FALSE;

	tmp = g_strstrip (g_strdup (*yes_no));
	checked_yes_no = nmc_string_is_valid (tmp, strv, NULL);
	g_free (tmp);
	if (g_strcmp0 (checked_yes_no, WORD_LOC_YES) == 0) {
		g_free (*yes_no);
		*yes_no = g_strdup (WORD_YES);
	} else if (g_strcmp0 (checked_yes_no, WORD_LOC_NO) == 0) {
		g_free (*yes_no);
		*yes_no = g_strdup (WORD_NO);
	}
	return !!checked_yes_no;
}

static gboolean
want_provide_opt_args (const char *type, int num)
{
	char *answer;
	gboolean ret = TRUE;

	/* Ask for optional arguments. */
	g_print (ngettext ("There is %d optional argument for '%s' connection type.\n",
	                   "There are %d optional arguments for '%s' connection type.\n", num),
	         num, type);
	answer = nmc_readline (ngettext ("Do you want to provide it? %s",
	                                 "Do you want to provide them? %s", num),
	                       prompt_yes_no (TRUE, NULL));
	answer = answer ? g_strstrip (answer) : NULL;
	if (answer && matches (answer, WORD_LOC_YES) != 0)
		ret = FALSE;
	g_free (answer);
	return ret;
}

static void
do_questionnaire_ethernet (gboolean ethernet, char **mtu, char **mac, char **cloned_mac)
{
	gboolean once_more;
	GError *error = NULL;

	/* Ask for optional arguments */
	if (ethernet && !want_provide_opt_args (_("ethernet"), 3))
		return;

	if (!*mtu) {
		do {
			*mtu = nmc_readline (_("MTU [auto]: "));
			once_more = !check_and_convert_mtu (*mtu, NULL, &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mtu);
			}
		} while (once_more);
	}
	if (!*mac) {
		do {
			*mac = nmc_readline (_("MAC [none]: "));
			once_more = !check_mac (*mac, ARPHRD_ETHER, "mac", &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mac);
			}
		} while (once_more);
	}
	if (!*cloned_mac) {
		do {
			*cloned_mac = nmc_readline (_("Cloned MAC [none]: "));
			once_more = !check_mac (*cloned_mac, ARPHRD_ETHER, "cloned-mac", &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*cloned_mac);
			}
		} while (once_more);
	}
}

#define WORD_DATAGRAM  "datagram"
#define WORD_CONNECTED "connected"
#define PROMPT_IB_MODE "(" WORD_DATAGRAM "/" WORD_CONNECTED ") [" WORD_DATAGRAM "]: "
static void
do_questionnaire_infiniband (char **mtu, char **mac, char **mode, char **parent, char **p_key)
{
	gboolean once_more;
	GError *error = NULL;

	/* Ask for optional arguments */
	if (!want_provide_opt_args (_("InfiniBand"), 5))
		return;

	if (!*mtu) {
		do {
			*mtu = nmc_readline (_("MTU [auto]: "));
			once_more = !check_and_convert_mtu (*mtu, NULL, &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mtu);
			}
		} while (once_more);
	}
	if (!*mac) {
		do {
			*mac = nmc_readline (_("MAC [none]: "));
			once_more = !check_mac (*mac, ARPHRD_INFINIBAND, "mac", &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mac);
			}
		} while (once_more);
	}
	if (!*mode) {
		do {
			*mode = nmc_readline (_("Transport mode %s"), PROMPT_IB_MODE);
			if (!*mode)
				*mode = g_strdup ("datagram");
			once_more = !check_infiniband_mode (mode, &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mode);
			}
		} while (once_more);
	}
	if (!*parent) {
		do {
			*parent = nmc_readline (_("Parent interface [none]: "));
			once_more = !check_infiniband_parent (*parent, &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*parent);
			}
		} while (once_more);
	}
	if (!*p_key) {
		do {
			*p_key = nmc_readline (_("P_KEY [none]: "));
			once_more = !check_infiniband_p_key (*p_key, NULL, &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*p_key);
			}
			/* If parent is specified, so has to be P_KEY */
			if (!once_more && *parent && !*p_key) {
				once_more = TRUE;
				g_print (_("Error: 'p-key' is mandatory when 'parent' is specified.\n"));
			}
		} while (once_more);
	}
}

#define WORD_INFRA  "infrastructure"
#define WORD_AP     "ap"
#define WORD_ADHOC  "adhoc"
#define PROMPT_WIFI_MODE "(" WORD_INFRA "/" WORD_AP "/" WORD_ADHOC ") [" WORD_INFRA "]: "
static void
do_questionnaire_wifi (char **mtu, char **mac, char **cloned_mac, char **mode)
{
	gboolean once_more;
	GError *error = NULL;

	/* Ask for optional arguments */
	if (!want_provide_opt_args (_("Wi-Fi"), 4))
		return;

	/* Most optional Wi-Fi arguments are the same as for ethernet. */
	do_questionnaire_ethernet (FALSE, mtu, mac, cloned_mac);

	if (!*mode) {
		do {
			*mode = nmc_readline (_("Mode %s"), PROMPT_WIFI_MODE);
			if (!*mode)
				*mode = g_strdup ("infrastructure");
			once_more = !check_wifi_mode (mode, &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mode);
			}
		} while (once_more);
	}
}

static void
do_questionnaire_wimax (char **mac)
{
	gboolean once_more;
	GError *error = NULL;

	/* Ask for optional 'wimax' arguments. */
	if (!want_provide_opt_args (_("WiMAX"), 1))
		return;

	if (!*mac) {
		do {
			*mac = nmc_readline (_("MAC [none]: "));
			once_more = !check_mac (*mac, ARPHRD_ETHER, "mac", &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mac);
			}
		} while (once_more);
	}
}

static void
do_questionnaire_pppoe (char **password, char **service, char **mtu, char **mac)
{
	gboolean once_more;
	GError *error = NULL;

	/* Ask for optional 'pppoe' arguments. */
	if (!want_provide_opt_args (_("PPPoE"), 4))
		return;

	if (!*password)
		*password = nmc_readline (_("Password [none]: "));
	if (!*service)
		*service = nmc_readline (_("Service [none]: "));

	if (!*mtu) {
		do {
			*mtu = nmc_readline (_("MTU [auto]: "));
			once_more = !check_and_convert_mtu (*mtu, NULL, &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mtu);
			}
		} while (once_more);
	}
	if (!*mac) {
		do {
			*mac = nmc_readline (_("MAC [none]: "));
			once_more = !check_mac (*mac, ARPHRD_ETHER, "mac", &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mac);
			}
		} while (once_more);
	}
}

static void
do_questionnaire_mobile (char **user, char **password)
{
	/* Ask for optional 'gsm' or 'cdma' arguments. */
	if (!want_provide_opt_args (_("mobile broadband"), 2))
		return;

	if (!*user)
		*user = nmc_readline (_("Username [none]: "));
	if (!*password)
		*password = nmc_readline (_("Password [none]: "));
}

#define WORD_PANU      "panu"
#define WORD_DUN_GSM   "dun-gsm"
#define WORD_DUN_CDMA  "dun-cdma"
#define PROMPT_BT_TYPE "(" WORD_PANU "/" WORD_DUN_GSM "/" WORD_DUN_CDMA ") [" WORD_PANU "]: "
static void
do_questionnaire_bluetooth (char **bt_type)
{
	gboolean once_more;

	/* Ask for optional 'bluetooth' arguments. */
	if (!want_provide_opt_args (_("bluetooth"), 1))
		return;

	if (!*bt_type) {
		const char *types[] = { "dun", "dun-gsm", "dun-cdma", "panu", NULL };
		const char *tmp;
		do {
			*bt_type = nmc_readline (_("Bluetooth type %s"), PROMPT_BT_TYPE);
			if (!*bt_type)
				*bt_type = g_strdup ("panu");
			tmp = nmc_string_is_valid (*bt_type, types, NULL);
			once_more = !tmp;
			if (once_more) {
				g_print (_("Error: 'bt-type': '%s' is not a valid bluetooth type.\n"), *bt_type);
				g_free (*bt_type);
			}
		} while (once_more);
		g_free (*bt_type);
		*bt_type = g_strdup (tmp);
	}
}

static void
do_questionnaire_vlan (char **mtu, char **flags, char **ingress, char **egress)
{
	gboolean once_more;
	GError *error = NULL;

	/* Ask for optional 'vlan' arguments. */
	if (!want_provide_opt_args (_("VLAN"), 4))
		return;

	if (!*mtu) {
		do {
			*mtu = nmc_readline (_("MTU [auto]: "));
			once_more = !check_and_convert_mtu (*mtu, NULL, &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mtu);
			}
		} while (once_more);
	}
	if (!*flags) {
		do {
			*flags = nmc_readline (_("VLAN flags (<0-7>) [none]: "));
			once_more = !check_and_convert_vlan_flags (*flags, NULL, &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*flags);
			}
		} while (once_more);
	}
	if (!*ingress) {
		do {
			*ingress = nmc_readline (_("Ingress priority maps [none]: "));
			once_more = !check_and_convert_vlan_prio_maps (*ingress, NM_VLAN_INGRESS_MAP, NULL, &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*ingress);
			}
		} while (once_more);
	}
	if (!*egress) {
		do {
			*egress = nmc_readline (_("Egress priority maps [none]: "));
			once_more = !check_and_convert_vlan_prio_maps (*egress, NM_VLAN_EGRESS_MAP, NULL, &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*egress);
			}
		} while (once_more);
	}
}

#define PROMPT_BOND_MODE _("Bonding mode [balance-rr]: ")
#define WORD_MIIMON "miimon"
#define WORD_ARP    "arp"
#define PROMPT_BOND_MON_MODE "(" WORD_MIIMON "/" WORD_ARP ") [" WORD_MIIMON "]: "
static void
do_questionnaire_bond (char **mode, char **primary, char **miimon,
                       char **downdelay, char **updelay,
                       char **arpinterval, char **arpiptarget,
                       char **lacp_rate)
{
	char *monitor_mode;
	unsigned long tmp;
	gboolean once_more;
	GError *error = NULL;

	/* Ask for optional 'bond' arguments. */
	if (!want_provide_opt_args (_("bond"), 5))
		return;

	if (!*mode) {
		const char *mode_tmp;
		do {
			*mode = nmc_readline (PROMPT_BOND_MODE);
			if (!*mode)
				*mode = g_strdup ("balance-rr");
			mode_tmp = nmc_bond_validate_mode (*mode, &error);
			g_free (*mode);
			if (mode_tmp) {
				*mode = g_strdup (mode_tmp);
			} else {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
			}
		} while (!mode_tmp);
	}

	if (g_strcmp0 (*mode, "active-backup") == 0 && !*primary) {
		do {
			*primary = nmc_readline (_("Bonding primary interface [none]: "));
			once_more = *primary && !nm_utils_iface_valid_name (*primary);
			if (once_more) {
				g_print (_("Error: 'primary': '%s' is not a valid interface name.\n"),
				         *primary);
				g_free (*primary);
			}
		} while (once_more);
	}

	do {
		monitor_mode = nmc_readline (_("Bonding monitoring mode %s"), PROMPT_BOND_MON_MODE);
		if (!monitor_mode)
			monitor_mode = g_strdup (WORD_MIIMON);
		g_strstrip (monitor_mode);
		once_more = matches (monitor_mode, WORD_MIIMON) != 0 && matches (monitor_mode, WORD_ARP) != 0;
		if (once_more) {
			g_print (_("Error: '%s' is not a valid monitoring mode; use '%s' or '%s'.\n"),
			         monitor_mode, WORD_MIIMON, WORD_ARP);
			g_free (monitor_mode);
		}
	} while (once_more);

	if (matches (monitor_mode, WORD_MIIMON) == 0) {
		if (!*miimon) {
			do {
				*miimon = nmc_readline (_("Bonding miimon [100]: "));
				once_more = *miimon && !nmc_string_to_uint (*miimon, TRUE, 0, G_MAXUINT32, &tmp);
				if (once_more) {
					g_print (_("Error: 'miimon': '%s' is not a valid number <0-%u>.\n"),
					         *miimon, G_MAXUINT32);
					g_free (*miimon);
				}
			} while (once_more);
		}
		if (!*downdelay) {
			do {
				*downdelay = nmc_readline (_("Bonding downdelay [0]: "));
				once_more = *downdelay && !nmc_string_to_uint (*downdelay, TRUE, 0, G_MAXUINT32, &tmp);
				if (once_more) {
					g_print (_("Error: 'downdelay': '%s' is not a valid number <0-%u>.\n"),
					         *downdelay, G_MAXUINT32);
					g_free (*downdelay);
				}
			} while (once_more);
		}
		if (!*updelay) {
			do {
				*updelay = nmc_readline (_("Bonding updelay [0]: "));
				once_more = *updelay && !nmc_string_to_uint (*updelay, TRUE, 0, G_MAXUINT32, &tmp);
				if (once_more) {
					g_print (_("Error: 'updelay': '%s' is not a valid number <0-%u>.\n"),
					         *updelay, G_MAXUINT32);
					g_free (*updelay);
				}
			} while (once_more);
		}
	} else {
		if (!*arpinterval) {
			do {
				*arpinterval = nmc_readline (_("Bonding arp-interval [0]: "));
				once_more = *arpinterval && !nmc_string_to_uint (*arpinterval, TRUE, 0, G_MAXUINT32, &tmp);
				if (once_more) {
					g_print (_("Error: 'arp-interval': '%s' is not a valid number <0-%u>.\n"),
					         *arpinterval, G_MAXUINT32);
					g_free (*arpinterval);
				}
			} while (once_more);
		}
		if (!*arpiptarget) {
			//FIXME: verify the string
			*arpiptarget = nmc_readline (_("Bonding arp-ip-target [none]: "));
		}
	}

	if (   !*lacp_rate
	    && (g_strcmp0 (*mode, "802.3ad") == 0 || g_strcmp0 (*mode, "4") == 0)) {
		do {
			*lacp_rate = nmc_readline (_("LACP rate ('slow' or 'fast') [slow]: "));
			once_more = *lacp_rate && (strcmp (*lacp_rate, "slow") &&
			                           strcmp (*lacp_rate, "0") &&
			                           strcmp (*lacp_rate, "fast") &&
			                           strcmp (*lacp_rate, "1"));
			if (once_more) {
				printf (_("Error: 'lacp_rate': '%s' is invalid ('slow' or 'fast').\n"),
				        *lacp_rate);
				g_free (*lacp_rate);
			}
		} while (once_more);
	}

	g_free (monitor_mode);
}

static void
do_questionnaire_team_common (const char *type_name, char **config)
{
	gboolean once_more;
	char *json = NULL;
	GError *error = NULL;

	/* Ask for optional arguments. */
	if (!want_provide_opt_args (type_name, 1))
		return;

	if (!*config) {
		do {
			*config = nmc_readline (_("Team JSON configuration [none]: "));
			once_more = !nmc_team_check_config (*config, &json, &error);
			if (once_more) {
				g_print ("Error: %s\n", error->message);
				g_clear_error (&error);
				g_free (*config);
			}
		} while (once_more);
	}

	*config = json;
}

/* Both team and team-slave curently have just ithe same one optional argument */
static void
do_questionnaire_team (char **config)
{
	do_questionnaire_team_common (_("team"), config);
}

static void
do_questionnaire_team_slave (char **config)
{
	do_questionnaire_team_common (_("team-slave"), config);
}

static void
do_questionnaire_bridge (char **stp, char **priority, char **fwd_delay, char **hello_time,
                         char **max_age, char **ageing_time, char **mcast_snoop, char **mac)
{
	unsigned long tmp;
	gboolean once_more;
	GError *error = NULL;

	/* Ask for optional 'bridge' arguments. */
	if (!want_provide_opt_args (_("bridge"), 8))
		return;

	if (!*stp) {
		gboolean stp_bool;
		do {
			*stp = nmc_readline (_("Enable STP %s"), prompt_yes_no (TRUE, ":"));
			*stp = *stp ? *stp : g_strdup ("yes");
			normalize_yes_no (stp);
			once_more = !nmc_string_to_bool (*stp, &stp_bool, &error);
			if (once_more) {
				g_print (_("Error: 'stp': %s.\n"), error->message);
				g_clear_error (&error);
				g_free (*stp);
			}
		} while (once_more);
	}
	if (!*priority) {
		do {
			*priority = nmc_readline (_("STP priority [32768]: "));
			*priority = *priority ? *priority : g_strdup ("32768");
			once_more = !nmc_string_to_uint (*priority, TRUE, 0, G_MAXUINT16, &tmp);
			if (once_more) {
				g_print (_("Error: 'priority': '%s' is not a valid number <0-%d>.\n"),
				         *priority, G_MAXUINT16);
				g_free (*priority);
			}
		} while (once_more);
	}
	if (!*fwd_delay) {
		do {
			*fwd_delay = nmc_readline (_("Forward delay [15]: "));
			*fwd_delay = *fwd_delay ? *fwd_delay : g_strdup ("15");
			once_more = !nmc_string_to_uint (*fwd_delay, TRUE, 2, 30, &tmp);
			if (once_more) {
				g_print (_("Error: 'forward-delay': '%s' is not a valid number <2-30>.\n"),
				         *fwd_delay);
				g_free (*fwd_delay);
			}
		} while (once_more);
	}

	if (!*hello_time) {
		do {
			*hello_time = nmc_readline (_("Hello time [2]: "));
			*hello_time = *hello_time ? *hello_time : g_strdup ("2");
			once_more = !nmc_string_to_uint (*hello_time, TRUE, 1, 10, &tmp);
			if (once_more) {
				g_print (_("Error: 'hello-time': '%s' is not a valid number <1-10>.\n"),
				         *hello_time);
				g_free (*hello_time);
			}
		} while (once_more);
	}
	if (!*max_age) {
		do {
			*max_age = nmc_readline (_("Max age [20]: "));
			*max_age = *max_age ? *max_age : g_strdup ("20");
			once_more = !nmc_string_to_uint (*max_age, TRUE, 6, 40, &tmp);
			if (once_more) {
				g_print (_("Error: 'max-age': '%s' is not a valid number <6-40>.\n"),
				         *max_age);
				g_free (*max_age);
			}
		} while (once_more);
	}
	if (!*ageing_time) {
		do {
			*ageing_time = nmc_readline (_("MAC address ageing time [300]: "));
			*ageing_time = *ageing_time ? *ageing_time : g_strdup ("300");
			once_more = !nmc_string_to_uint (*ageing_time, TRUE, 0, 1000000, &tmp);
			if (once_more) {
				g_print (_("Error: 'ageing-time': '%s' is not a valid number <0-1000000>.\n"),
				         *ageing_time);
				g_free (*ageing_time);
			}
		} while (once_more);
	}
	if (!*mcast_snoop) {
		gboolean mcast_snoop_bool;
		do {
			*mcast_snoop = nmc_readline (_("Enable IGMP snooping %s"), prompt_yes_no (TRUE, ":"));
			*mcast_snoop = *mcast_snoop ? *mcast_snoop : g_strdup ("yes");
			normalize_yes_no (mcast_snoop);
			once_more = !nmc_string_to_bool (*mcast_snoop, &mcast_snoop_bool, &error);
			if (once_more) {
				g_print (_("Error: 'multicast-snooping': %s.\n"), error->message);
				g_clear_error (&error);
				g_free (*mcast_snoop);
			}
		} while (once_more);
	}
	if (!*mac) {
		do {
			*mac = nmc_get_user_input (_("MAC [none]: "));
			once_more = !check_mac (*mac, ARPHRD_ETHER, "mac", &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*mac);
			}
		} while (once_more);
	}
}

static void
do_questionnaire_bridge_slave (char **priority, char **path_cost, char **hairpin)
{
	unsigned long tmp;
	gboolean once_more;
	GError *error = NULL;

	/* Ask for optional 'bridge-slave' arguments. */
	if (!want_provide_opt_args (_("bridge-slave"), 3))
		return;

	if (!*priority) {
		do {
			*priority = nmc_readline (_("Bridge port priority [32]: "));
			*priority = *priority ? *priority : g_strdup ("32");
			once_more = !bridge_prop_string_to_uint (*priority, "priority", NM_TYPE_SETTING_BRIDGE_PORT,
			                                         NM_SETTING_BRIDGE_PORT_PRIORITY, &tmp, &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*priority);
			}
		} while (once_more);
	}
	if (!*path_cost) {
		do {
			*path_cost = nmc_readline (_("Bridge port STP path cost [100]: "));
			*path_cost = *path_cost ? *path_cost : g_strdup ("100");
			once_more = !bridge_prop_string_to_uint (*path_cost, "path-cost", NM_TYPE_SETTING_BRIDGE_PORT,
			                                         NM_SETTING_BRIDGE_PORT_PATH_COST, &tmp, &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*path_cost);
			}
		} while (once_more);
	}
	if (!*hairpin) {
		gboolean hairpin_bool;
		do {
			*hairpin = nmc_readline (_("Hairpin %s"), prompt_yes_no (TRUE, ":"));
			*hairpin = *hairpin ? *hairpin : g_strdup ("yes");
			normalize_yes_no (hairpin);
			once_more = !nmc_string_to_bool (*hairpin, &hairpin_bool, &error);
			if (once_more) {
				g_print (_("Error: 'hairpin': %s.\n"), error->message);
				g_clear_error (&error);
				g_free (*hairpin);
			}
		} while (once_more);
	}
}

static void
do_questionnaire_vpn (char **user)
{
	/* Ask for optional 'vpn' arguments. */
	if (!want_provide_opt_args (_("VPN"), 1))
		return;

	if (!*user)
		*user = nmc_readline (_("Username [none]: "));
}

static void
do_questionnaire_olpc (char **channel, char **dhcp_anycast)
{
	unsigned long tmp;
	gboolean once_more;
	GError *error = NULL;

	/* Ask for optional 'olpc' arguments. */
	if (!want_provide_opt_args (_("OLPC Mesh"), 2))
		return;

	if (!*channel) {
		do {
			*channel = nmc_readline (_("OLPC Mesh channel [1]: "));
			once_more = *channel && !nmc_string_to_uint (*channel, TRUE, 1, 13, &tmp);
			if (once_more) {
				g_print (_("Error: 'channel': '%s' is not a valid number <1-13>.\n"),
				         *channel);
				g_free (*channel);
			}
		} while (once_more);
	}
	if (!*dhcp_anycast) {
		do {
			*dhcp_anycast = nmc_readline (_("DHCP anycast MAC address [none]: "));
			once_more = !check_mac (*dhcp_anycast, ARPHRD_ETHER, "dhcp-anycast", &error);
			if (once_more) {
				g_print ("%s\n", error->message);
				g_clear_error (&error);
				g_free (*dhcp_anycast);
			}
		} while (once_more);
	}
}

static gboolean
split_address (char* str, char **ip, char **rest)
{
	size_t n1, n2, n3;

	*ip = *rest = NULL;
	if (!str)
		return FALSE;

	n1 = strspn  (str,    " \t");
	n2 = strcspn (str+n1, " \t\0") + n1;
	n3 = strspn  (str+n2, " \t")   + n2;

	str[n2] = '\0';
	*ip = str[n1] ? str + n1 : NULL;
	*rest = str[n3] ? str + n3 : NULL;

	return TRUE;
}

static void
ask_for_ip_addresses (NMConnection *connection, int family)
{
	gboolean ip_loop;
	GError *error = NULL;
	char *str, *ip, *rest;
	const char *prompt;
	gboolean added;
	NMIPAddress *ipaddr;

	if (family == AF_INET)
		prompt =_("IPv4 address (IP[/plen]) [none]: ");
	else
		prompt =_("IPv6 address (IP[/plen]) [none]: ");

	ip_loop = TRUE;
	do {
		str = nmc_readline ("%s", prompt);
		split_address (str, &ip, &rest);
		if (ip) {
			ipaddr = nmc_parse_and_build_address (family, ip, &error);
			if (ipaddr) {
				if (family == AF_INET)
					added = add_ip4_address_to_connection (ipaddr, connection);
				else
					added = add_ip6_address_to_connection (ipaddr, connection);
				if (added)
					g_print (_("  Address successfully added: %s\n"), ip);
				else
					g_print (_("  Warning: address already present: %s\n"), ip);
				if (rest)
					g_print (_("  Warning: ignoring garbage at the end: '%s'\n"), rest);
			} else {
				g_prefix_error (&error, _("Error: "));
				g_print ("%s\n", error->message);
				g_clear_error (&error);
			}
		} else
			ip_loop = FALSE;

		g_free (str);
	} while (ip_loop);
}

static void
maybe_ask_for_gateway (NMConnection *connection, int family)
{
	gboolean gw_loop;
	char *str, *gw, *rest;
	const char *prompt;
	NMSettingIPConfig *s_ip;

	if (family == AF_INET) {
		prompt =_("IPv4 gateway [none]: ");
		s_ip = nm_connection_get_setting_ip4_config (connection);
	} else {
		prompt =_("IPv6 gateway [none]: ");
		s_ip = nm_connection_get_setting_ip6_config (connection);
	}
	if (s_ip == NULL)
		return;
	if (   nm_setting_ip_config_get_num_addresses (s_ip) == 0
	    || nm_setting_ip_config_get_gateway (s_ip) != NULL)
		return;

	gw_loop = TRUE;
	do {
		str = nmc_readline ("%s", prompt);
		split_address (str, &gw, &rest);
		if (gw) {
			if (nm_utils_ipaddr_valid (family, gw)) {
				g_object_set (s_ip,
				              NM_SETTING_IP_CONFIG_GATEWAY, gw,
				              NULL);
				gw_loop = FALSE;
			} else
				g_print (_("Error: invalid gateway address '%s'\n"), gw);
		} else
			gw_loop = FALSE;
		g_free (str);
	} while (gw_loop);
}

static void
do_questionnaire_ip (NMConnection *connection)
{
	char *answer;

	/* Ask for IP addresses */
	answer = nmc_readline (_("Do you want to add IP addresses? %s"), prompt_yes_no (TRUE, NULL));
	answer = answer ? g_strstrip (answer) : NULL;
	if (answer && matches (answer, WORD_LOC_YES) != 0) {
		g_free (answer);
		return;
	}
	g_free (answer);

	g_print (_("Press <Enter> to finish adding addresses.\n"));

	ask_for_ip_addresses (connection, AF_INET);
	maybe_ask_for_gateway (connection, AF_INET);
	ask_for_ip_addresses (connection, AF_INET6);
	maybe_ask_for_gateway (connection, AF_INET6);
}

static gboolean
complete_connection_by_type (NMConnection *connection,
                             const char *con_type,
                             const GPtrArray *all_connections,
                             gboolean ask,
                             int argc,
                             char **argv,
                             GError **error)
{
	NMSettingConnection *s_con;
	NMSettingGeneric *s_generic;
	NMSettingWired *s_wired;
	NMSettingInfiniband *s_infiniband;
	NMSettingWireless *s_wifi;
	NMSettingWimax *s_wimax;
	NMSettingPppoe *s_pppoe;
	NMSettingGsm *s_gsm;
	NMSettingCdma *s_cdma;
	NMSettingBluetooth *s_bt;
	NMSettingVlan *s_vlan;
	NMSettingBond *s_bond;
	NMSettingTeam *s_team;
	NMSettingTeamPort *s_team_port;
	NMSettingBridge *s_bridge;
	NMSettingBridgePort *s_bridge_port;
	NMSettingVpn *s_vpn;
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
		nmc_arg_t exp_args[] = { {"mtu",        TRUE, &mtu_c,        FALSE},
		                         {"mac",        TRUE, &mac_c,        FALSE},
		                         {"cloned-mac", TRUE, &cloned_mac_c, FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		/* Also ask for all optional arguments if '--ask' is specified. */
		mtu = g_strdup (mtu_c);
		mac = g_strdup (mac_c);
		cloned_mac = g_strdup (cloned_mac_c);
		if (ask)
			do_questionnaire_ethernet (TRUE, &mtu, &mac, &cloned_mac);

		if (!check_and_convert_mtu (mtu, &mtu_int, error))
			goto cleanup_wired;
		if (!check_mac (mac, ARPHRD_ETHER, "mac", error))
			goto cleanup_wired;
		if (!check_mac (cloned_mac, ARPHRD_ETHER, "cloned-mac", error))
			goto cleanup_wired;

		/* Add ethernet setting */
		s_wired = (NMSettingWired *) nm_setting_wired_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wired));

		if (mtu)
			g_object_set (s_wired, NM_SETTING_WIRED_MTU, mtu_int, NULL);
		if (mac)
			g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, mac, NULL);
		if (cloned_mac)
			g_object_set (s_wired, NM_SETTING_WIRED_CLONED_MAC_ADDRESS, cloned_mac, NULL);

		success = TRUE;
cleanup_wired:
		g_free (mtu);
		g_free (mac);
		g_free (cloned_mac);
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
		mtu = g_strdup (mtu_c);
		mac = g_strdup (mac_c);
		mode = g_strdup (mode_c);
		parent = g_strdup (parent_c);
		p_key = g_strdup (p_key_c);
		if (ask)
			do_questionnaire_infiniband (&mtu, &mac, &mode, &parent, &p_key);

		if (!check_and_convert_mtu (mtu, &mtu_int, error))
			goto cleanup_ib;
		if (!check_mac (mac, ARPHRD_INFINIBAND, "mac", error))
			goto cleanup_ib;
		if (!check_infiniband_mode (&mode, error))
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
		if (mac)
			g_object_set (s_infiniband, NM_SETTING_INFINIBAND_MAC_ADDRESS, mac, NULL);
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
		GBytes *ssid_bytes;
		const char *mtu_c = NULL;
		char *mtu = NULL;
		guint32 mtu_int = 0;
		const char *mac_c = NULL;
		char *mac = NULL;
		const char *cloned_mac_c = NULL;
		char *cloned_mac = NULL;
		const char *mode_c = NULL;
		char *mode = NULL;
		nmc_arg_t exp_args[] = { {"ssid",       TRUE, &ssid,         !ask},
		                         {"mtu",        TRUE, &mtu_c,        FALSE},
		                         {"mac",        TRUE, &mac_c,        FALSE},
		                         {"cloned-mac", TRUE, &cloned_mac_c, FALSE},
		                         {"mode",       TRUE, &mode_c,       FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (!ssid && ask)
			ssid = ssid_ask = nmc_readline (_("SSID: "));
		if (!ssid) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'ssid' is required."));
			return FALSE;
		}

		/* Also ask for all optional arguments if '--ask' is specified. */
		mtu = g_strdup (mtu_c);
		mac = g_strdup (mac_c);
		cloned_mac = g_strdup (cloned_mac_c);
		mode = g_strdup (mode_c);
		if (ask)
			do_questionnaire_wifi (&mtu, &mac, &cloned_mac, &mode);

		if (!check_and_convert_mtu (mtu, &mtu_int, error))
			goto cleanup_wifi;
		if (!check_mac (mac, ARPHRD_ETHER, "mac", error))
			goto cleanup_wifi;
		if (!check_mac (cloned_mac, ARPHRD_ETHER, "cloned-mac", error))
			goto cleanup_wifi;
		if (!check_wifi_mode (&mode, error))
			goto cleanup_wifi;

		/* Add wifi setting */
		s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wifi));

		ssid_bytes = g_bytes_new (ssid, strlen (ssid));
		g_object_set (s_wifi, NM_SETTING_WIRELESS_SSID, ssid_bytes, NULL);

		if (mtu)
			g_object_set (s_wifi, NM_SETTING_WIRELESS_MTU, mtu_int, NULL);
		if (mac)
			g_object_set (s_wifi, NM_SETTING_WIRELESS_MAC_ADDRESS, mac, NULL);
		if (cloned_mac)
			g_object_set (s_wifi, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, cloned_mac, NULL);
		if (mode)
			g_object_set (s_wifi, NM_SETTING_WIRELESS_MODE, mode, NULL);

		g_bytes_unref (ssid_bytes);

		success = TRUE;
cleanup_wifi:
		g_free (ssid_ask);
		g_free (mtu);
		g_free (mac);
		g_free (cloned_mac);
		g_free (mode);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, NM_SETTING_WIMAX_SETTING_NAME)) {
		/* Build up the settings required for 'wimax' */
		gboolean success = FALSE;
		const char *nsp_name = NULL;
		char *nsp_name_ask = NULL;
		const char *mac_c = NULL;
		char *mac = NULL;
		nmc_arg_t exp_args[] = { {"nsp", TRUE, &nsp_name, !ask},
		                         {"mac", TRUE, &mac_c,    FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (!nsp_name && ask)
			nsp_name = nsp_name_ask = nmc_readline (_("WiMAX NSP name: "));
		if (!nsp_name) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'nsp' is required."));
			goto cleanup_wimax;
		}

		/* Also ask for all optional arguments if '--ask' is specified. */
		mac = g_strdup (mac_c);
		if (ask)
			do_questionnaire_wimax (&mac);

		if (!check_mac (mac, ARPHRD_ETHER, "mac", error))
			goto cleanup_wimax;

		/* Add 'wimax' setting */
		s_wimax = (NMSettingWimax *) nm_setting_wimax_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wimax));
		g_object_set (s_wimax, NM_SETTING_WIMAX_NETWORK_NAME, nsp_name, NULL);

		if (mac)
			g_object_set (s_wimax, NM_SETTING_WIMAX_MAC_ADDRESS, mac, NULL);

		success = TRUE;
cleanup_wimax:
		g_free (nsp_name_ask);
		g_free (mac);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, NM_SETTING_PPPOE_SETTING_NAME)) {
		/* Build up the settings required for 'pppoe' */
		gboolean success = FALSE;
		const char *username = NULL;
		char *username_ask = NULL;
		const char *password_c = NULL;
		char *password = NULL;
		const char *service_c = NULL;
		char *service = NULL;
		const char *mtu_c = NULL;
		char *mtu = NULL;
		guint32 mtu_int = 0;
		const char *mac_c = NULL;
		char *mac = NULL;
		nmc_arg_t exp_args[] = { {"username", TRUE, &username,   !ask},
		                         {"password", TRUE, &password_c, FALSE},
		                         {"service",  TRUE, &service_c,  FALSE},
		                         {"mtu",      TRUE, &mtu_c,      FALSE},
		                         {"mac",      TRUE, &mac_c,      FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (!username && ask)
			username = username_ask = nmc_readline (_("PPPoE username: "));
		if (!username) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'username' is required."));
			goto cleanup_pppoe;
		}

		/* Also ask for all optional arguments if '--ask' is specified. */
		password = g_strdup (password_c);
		service = g_strdup (service_c);
		mtu = g_strdup (mtu_c);
		mac = g_strdup (mac_c);
		if (ask)
			do_questionnaire_pppoe (&password, &service, &mtu, &mac);

		if (!check_and_convert_mtu (mtu, &mtu_int, error))
			goto cleanup_pppoe;
		if (!check_mac (mac, ARPHRD_ETHER, "mac", error))
			goto cleanup_pppoe;

		/* Add 'pppoe' setting */
		s_pppoe = (NMSettingPppoe *) nm_setting_pppoe_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_pppoe));
		g_object_set (s_pppoe, NM_SETTING_PPPOE_USERNAME, username, NULL);
		g_object_set (s_pppoe, NM_SETTING_PPPOE_PASSWORD, password, NULL);
		g_object_set (s_pppoe, NM_SETTING_PPPOE_SERVICE, service, NULL);

		/* Add ethernet setting */
		s_wired = (NMSettingWired *) nm_setting_wired_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wired));
		if (mtu)
			g_object_set (s_wired, NM_SETTING_WIRED_MTU, mtu_int, NULL);
		if (mac)
			g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, mac, NULL);

		success = TRUE;
cleanup_pppoe:
		g_free (username_ask);
		g_free (password);
		g_free (service);
		g_free (mtu);
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
			apn = apn_ask = nmc_readline (_("APN: "));
		if (!apn && is_gsm) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'apn' is required."));
			goto cleanup_mobile;
		}

		/* Also ask for all optional arguments if '--ask' is specified. */
		user = g_strdup (user_c);
		password = g_strdup (password_c);
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
		nmc_arg_t exp_args[] = { {"addr",    TRUE, &addr,      !ask},
		                         {"bt-type", TRUE, &bt_type_c, FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (!addr && ask)
			addr = addr_ask = nmc_readline (_("Bluetooth device address: "));
		if (!addr) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'addr' is required."));
			return FALSE;
		}
		if (!check_mac (addr, ARPHRD_ETHER, "addr", error))
			goto cleanup_bt;

		/* Also ask for all optional arguments if '--ask' is specified. */
		bt_type = g_strdup (bt_type_c);
		if (ask)
			do_questionnaire_bluetooth (&bt_type);

		/* Default to 'panu' if bt-type is not provided. */
		if (!bt_type)
			bt_type = g_strdup (NM_SETTING_BLUETOOTH_TYPE_PANU);

		/* Add 'bluetooth' setting */
		s_bt = (NMSettingBluetooth *) nm_setting_bluetooth_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_bt));

		if (addr)
			g_object_set (s_bt, NM_SETTING_BLUETOOTH_BDADDR, addr, NULL);

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
			parent = parent_ask = nmc_readline (_("VLAN parent device or connection UUID: "));
		if (!parent) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'dev' is required."));
			return FALSE;
		}
		if (!vlan_id && ask)
			vlan_id = vlan_id_ask = nmc_readline (_("VLAN ID <0-4095>: "));
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

		if (   !(addr_array = nm_utils_hwaddr_atoba (parent, ETH_ALEN))
		    && !nm_utils_is_uuid (parent)
		    && !nm_utils_iface_valid_name (parent)) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("Error: 'dev': '%s' is neither UUID, interface name, nor MAC."),
			             parent);
			goto cleanup_vlan;
		}

		/* Also ask for all optional arguments if '--ask' is specified. */
		mtu = g_strdup (mtu_c);
		flags = g_strdup (flags_c);
		ingress = g_strdup (ingress_c);
		egress = g_strdup (egress_c);
		if (ask)
			do_questionnaire_vlan (&mtu, &flags, &ingress, &egress);

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
		const char *bond_lacp_rate_c = NULL;
		char *bond_lacp_rate = NULL;
		nmc_arg_t exp_args[] = { {"mode",          TRUE, &bond_mode_c,        FALSE},
		                         {"primary",       TRUE, &bond_primary_c,     FALSE},
		                         {"miimon",        TRUE, &bond_miimon_c,      FALSE},
		                         {"downdelay",     TRUE, &bond_downdelay_c,   FALSE},
		                         {"updelay",       TRUE, &bond_updelay_c,     FALSE},
		                         {"arp-interval",  TRUE, &bond_arpinterval_c, FALSE},
		                         {"arp-ip-target", TRUE, &bond_arpiptarget_c, FALSE},
		                         {"lacp-rate",     TRUE, &bond_lacp_rate_c, FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		/* Also ask for all optional arguments if '--ask' is specified. */
		bond_mode = g_strdup (bond_mode_c);
		bond_primary = g_strdup (bond_primary_c);
		bond_miimon = g_strdup (bond_miimon_c);
		bond_downdelay = g_strdup (bond_downdelay_c);
		bond_updelay = g_strdup (bond_updelay_c);
		bond_arpinterval = g_strdup (bond_arpinterval_c);
		bond_arpiptarget = g_strdup (bond_arpiptarget_c);
		bond_lacp_rate = g_strdup (bond_lacp_rate_c);
		if (ask)
			do_questionnaire_bond (&bond_mode, &bond_primary, &bond_miimon,
			                       &bond_downdelay, &bond_updelay,
			                       &bond_arpinterval, &bond_arpiptarget,
			                       &bond_lacp_rate);

		/* Generate ifname if connection doesn't have one */
		ifname = nm_setting_connection_get_interface_name (s_con);
		if (!ifname) {
			char *bond_ifname = unique_master_iface_ifname (all_connections, "nm-bond");

			g_object_set (s_con,
			              NM_SETTING_CONNECTION_INTERFACE_NAME, bond_ifname,
			              NULL);
			g_free (bond_ifname);
		}

		/* Add 'bond' setting */
		s_bond = (NMSettingBond *) nm_setting_bond_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_bond));

		/* Set bond options */
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
		if (bond_lacp_rate)
			nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_LACP_RATE, bond_lacp_rate);

		success = TRUE;
cleanup_bond:
		g_free (bond_mode);
		g_free (bond_primary);
		g_free (bond_miimon);
		g_free (bond_downdelay);
		g_free (bond_updelay);
		g_free (bond_arpinterval);
		g_free (bond_arpiptarget);
		g_free (bond_lacp_rate);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, "bond-slave")) {
		/* Build up the settings required for 'bond-slave' */
		const char *master = NULL;
		char *master_ask = NULL;
		const char *checked_master = NULL;
		const char *type = NULL;
		nmc_arg_t exp_args[] = { {"master", TRUE, &master, !ask},
		                         {"type",   TRUE, &type,   FALSE},
		                         {NULL} };

		/* Set global variables for use in TAB completion */
		nmc_tab_completion.con_type = NM_SETTING_BOND_SETTING_NAME;

		if (!nmc_parse_args (exp_args, TRUE, &argc, &argv, error))
			return FALSE;

		if (!master && ask)
			master = master_ask = nmc_readline (PROMPT_BOND_MASTER);
		if (!master) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'master' is required."));
			return FALSE;
		}
		/* Verify master argument */
		checked_master = verify_master_for_slave (all_connections, master, NM_SETTING_BOND_SETTING_NAME);
		if (!checked_master)
			g_print (_("Warning: master='%s' doesn't refer to any existing profile.\n"), master);

		if (type)
			g_print (_("Warning: 'type' is currently ignored. "
			           "We only support ethernet slaves for now.\n"));

		/* Change properties in 'connection' setting */
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
		              NM_SETTING_CONNECTION_MASTER, checked_master ? checked_master : _strip_master_prefix (master, NULL),
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BOND_SETTING_NAME,
		              NULL);

		/* Add ethernet setting */
		s_wired = (NMSettingWired *) nm_setting_wired_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wired));

		g_free (master_ask);

	} else if (!strcmp (con_type, NM_SETTING_TEAM_SETTING_NAME)) {
		/* Build up the settings required for 'team' */
		gboolean success = FALSE;
		const char *ifname = NULL;
		const char *config_c = NULL;
		char *config = NULL;
		char *json = NULL;
		nmc_arg_t exp_args[] = { {"config", TRUE, &config_c, FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		/* Also ask for all optional arguments if '--ask' is specified. */
		config = g_strdup (config_c);
		if (ask)
			do_questionnaire_team (&config);

		/* Generate ifname if conneciton doesn't have one */
		ifname = nm_setting_connection_get_interface_name (s_con);
		if (!ifname) {
			char *team_ifname = unique_master_iface_ifname (all_connections, "nm-team");

			g_object_set (s_con,
			              NM_SETTING_CONNECTION_INTERFACE_NAME, team_ifname,
			              NULL);
			g_free (team_ifname);
		}

		/* Add 'team' setting */
		s_team = (NMSettingTeam *) nm_setting_team_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_team));

		if (!nmc_team_check_config (config, &json, error)) {
			g_prefix_error (error, _("Error: "));
			goto cleanup_team;
		}

		/* Set team options */
		g_object_set (s_team, NM_SETTING_TEAM_CONFIG, json, NULL);

		success = TRUE;
cleanup_team:
		g_free (config);
		g_free (json);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, "team-slave")) {
		/* Build up the settings required for 'team-slave' */
		gboolean success = FALSE;
		const char *master = NULL;
		char *master_ask = NULL;
		const char *checked_master = NULL;
		const char *type = NULL;
		const char *config_c = NULL;
		char *config = NULL;
		char *json = NULL;
		nmc_arg_t exp_args[] = { {"master", TRUE, &master,   !ask},
		                         {"type",   TRUE, &type,     FALSE},
		                         {"config", TRUE, &config_c, FALSE},
		                         {NULL} };

		/* Set global variables for use in TAB completion */
		nmc_tab_completion.con_type = NM_SETTING_TEAM_SETTING_NAME;

		if (!nmc_parse_args (exp_args, TRUE, &argc, &argv, error))
			return FALSE;

		if (!master && ask)
			master = master_ask = nmc_readline (PROMPT_TEAM_MASTER);
		if (!master) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'master' is required."));
			return FALSE;
		}
		/* Verify master argument */
		checked_master = verify_master_for_slave (all_connections, master, NM_SETTING_TEAM_SETTING_NAME);
		if (!checked_master)
			g_print (_("Warning: master='%s' doesn't refer to any existing profile.\n"), master);

		/* Also ask for all optional arguments if '--ask' is specified. */
		config = g_strdup (config_c);
		if (ask)
			do_questionnaire_team_slave (&config);

		if (type)
			g_print (_("Warning: 'type' is currently ignored. "
			           "We only support ethernet slaves for now.\n"));

		/* Add 'team-port' setting */
		s_team_port = (NMSettingTeamPort *) nm_setting_team_port_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_team_port));

		if (!nmc_team_check_config (config, &json, error)) {
			g_prefix_error (error, _("Error: "));
			goto cleanup_team_slave;
		}

		/* Set team-port options */
		g_object_set (s_team_port, NM_SETTING_TEAM_PORT_CONFIG, json, NULL);

		/* Change properties in 'connection' setting */
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
		              NM_SETTING_CONNECTION_MASTER, checked_master ? checked_master : _strip_master_prefix (master, NULL),
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_TEAM_SETTING_NAME,
		              NULL);

		/* Add ethernet setting */
		s_wired = (NMSettingWired *) nm_setting_wired_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wired));

		success = TRUE;
cleanup_team_slave:
		g_free (master_ask);
		g_free (config);
		g_free (json);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, NM_SETTING_BRIDGE_SETTING_NAME)) {
		/* Build up the settings required for 'bridge' */
		gboolean success = FALSE;
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
		const char *mcast_snoop_c = NULL;
		char *mcast_snoop = NULL;
		gboolean stp_bool, mcast_snoop_bool;
		unsigned long stp_prio_int, fwd_delay_int, hello_time_int,
		              max_age_int, ageing_time_int;
		const char *mac_c = NULL;
		char *mac = NULL;
		nmc_arg_t exp_args[] = { {"stp",           TRUE, &stp_c,         FALSE},
		                         {"priority",      TRUE, &priority_c,    FALSE},
		                         {"forward-delay", TRUE, &fwd_delay_c,   FALSE},
		                         {"hello-time",    TRUE, &hello_time_c,  FALSE},
		                         {"max-age",       TRUE, &max_age_c,     FALSE},
		                         {"ageing-time",   TRUE, &ageing_time_c, FALSE},
		                         {"multicast-snooping", TRUE, &mcast_snoop_c, FALSE},
		                         {"mac",           TRUE, &mac_c,         FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		/* Also ask for all optional arguments if '--ask' is specified. */
		stp = g_strdup (stp_c);
		priority = g_strdup (priority_c);
		fwd_delay = g_strdup (fwd_delay_c);
		hello_time = g_strdup (hello_time_c);
		max_age = g_strdup (max_age_c);
		ageing_time = g_strdup (ageing_time_c);
		mcast_snoop = g_strdup (mcast_snoop_c);
		mac = g_strdup (mac_c);
		if (ask)
			do_questionnaire_bridge (&stp, &priority, &fwd_delay, &hello_time,
			                         &max_age, &ageing_time, &mcast_snoop, &mac);

		/* Generate ifname if conneciton doesn't have one */
		ifname = nm_setting_connection_get_interface_name (s_con);
		if (!ifname) {
			char *bridge_ifname = unique_master_iface_ifname (all_connections, "nm-bridge");

			g_object_set (s_con,
			              NM_SETTING_CONNECTION_INTERFACE_NAME, bridge_ifname,
			              NULL);
			g_free (bridge_ifname);
		}

		if (stp) {
			GError *tmp_err = NULL;
			if (!nmc_string_to_bool (stp, &stp_bool, &tmp_err)) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'stp': %s."), tmp_err->message);
				g_clear_error (&tmp_err);
				goto cleanup_bridge;
			}
		}
		if (mcast_snoop) {
			GError *tmp_err = NULL;
			if (!nmc_string_to_bool (mcast_snoop, &mcast_snoop_bool, &tmp_err)) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: 'multicast-snooping': %s."), tmp_err->message);
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
		if (!check_mac (mac, ARPHRD_ETHER, "mac", error))
			goto cleanup_bridge;

		/* Set bridge options */
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
		if (mcast_snoop)
			g_object_set (s_bridge, NM_SETTING_BRIDGE_MULTICAST_SNOOPING, mcast_snoop_bool, NULL);
		if (mac)
			g_object_set (s_bridge, NM_SETTING_BRIDGE_MAC_ADDRESS, mac, NULL);

		success = TRUE;
cleanup_bridge:
		g_free (stp);
		g_free (priority);
		g_free (fwd_delay);
		g_free (hello_time);
		g_free (max_age);
		g_free (ageing_time);
		g_free (mcast_snoop);
		g_free (mac);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, "bridge-slave")) {
		/* Build up the settings required for 'bridge-slave' */
		gboolean success = FALSE;
		const char *master = NULL;
		char *master_ask = NULL;
		const char *checked_master = NULL;
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

		/* Set global variables for use in TAB completion */
		nmc_tab_completion.con_type = NM_SETTING_BRIDGE_SETTING_NAME;

		if (!nmc_parse_args (exp_args, TRUE, &argc, &argv, error))
			return FALSE;

		if (!master && ask)
			master = master_ask = nmc_readline (PROMPT_BRIDGE_MASTER);
		if (!master) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'master' is required."));
			return FALSE;
		}
		/* Verify master argument */
		checked_master = verify_master_for_slave (all_connections, master, NM_SETTING_BRIDGE_SETTING_NAME);
		if (!checked_master)
			g_print (_("Warning: master='%s' doesn't refer to any existing profile.\n"), master);

		if (type)
			g_print (_("Warning: 'type' is currently ignored. "
			           "We only support ethernet slaves for now.\n"));

		/* Add 'bridge-port' setting */
		/* Must be done *before* bridge_prop_string_to_uint() so that the type is known */
		s_bridge_port = (NMSettingBridgePort *) nm_setting_bridge_port_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_bridge_port));

		/* Also ask for all optional arguments if '--ask' is specified. */
		priority = g_strdup (priority_c);
		path_cost = g_strdup (path_cost_c);
		hairpin = g_strdup (hairpin_c);
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
		              NM_SETTING_CONNECTION_MASTER, checked_master ? checked_master : _strip_master_prefix (master, NULL),
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
		const char *vpn_type = NULL;
		char *vpn_type_ask = NULL;
		const char *user_c = NULL;
		char *user = NULL;
		const char *st;
		char *service_type = NULL;
		nmc_arg_t exp_args[] = { {"vpn-type", TRUE, &vpn_type, !ask},
		                         {"user",     TRUE, &user_c,   FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (!vpn_type && ask)
			vpn_type = vpn_type_ask = nmc_readline (PROMPT_VPN_TYPE);
		if (!vpn_type) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'vpn-type' is required."));
			goto cleanup_vpn;
		}
		if (vpn_type_ask)
			vpn_type = g_strstrip (vpn_type_ask);

		if (!(st = nmc_string_is_valid (vpn_type, nmc_known_vpns, NULL))) {
			g_print (_("Warning: 'vpn-type': %s not known.\n"), vpn_type);
			st = vpn_type;
		}
		service_type = g_strdup_printf ("%s.%s", NM_DBUS_INTERFACE, st);

		/* Also ask for all optional arguments if '--ask' is specified. */
		user = g_strdup (user_c);
		if (ask)
			do_questionnaire_vpn (&user);

		/* Add 'vpn' setting */
		s_vpn = (NMSettingVpn *) nm_setting_vpn_new ();
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
		GBytes *ssid_bytes;
		const char *channel_c = NULL;
		char *channel = NULL;
		unsigned long chan;
		const char *dhcp_anycast_c = NULL;
		char *dhcp_anycast = NULL;
		nmc_arg_t exp_args[] = { {"ssid",         TRUE, &ssid,           !ask},
		                         {"channel",      TRUE, &channel_c,      FALSE},
		                         {"dhcp-anycast", TRUE, &dhcp_anycast_c, FALSE},
		                         {NULL} };

		if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, error))
			return FALSE;

		if (!ssid && ask)
			ssid = ssid_ask = nmc_readline (_("SSID: "));
		if (!ssid) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: 'ssid' is required."));
			goto cleanup_olpc;
		}

		/* Also ask for all optional arguments if '--ask' is specified. */
		channel = g_strdup (channel_c);
		dhcp_anycast = g_strdup (dhcp_anycast_c);
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
		if (!check_mac (dhcp_anycast, ARPHRD_ETHER, "dhcp-anycast", error))
			goto cleanup_olpc;

		/* Add OLPC mesh setting */
		s_olpc_mesh = (NMSettingOlpcMesh *) nm_setting_olpc_mesh_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_olpc_mesh));

		ssid_bytes = g_bytes_new (ssid, strlen (ssid));
		g_object_set (s_olpc_mesh, NM_SETTING_OLPC_MESH_SSID, ssid_bytes, NULL);
		if (channel)
			g_object_set (s_olpc_mesh, NM_SETTING_OLPC_MESH_CHANNEL, chan, NULL);
		else
			g_object_set (s_olpc_mesh, NM_SETTING_OLPC_MESH_CHANNEL, 1, NULL);
		if (dhcp_anycast)
			g_object_set (s_olpc_mesh, NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS, dhcp_anycast, NULL);
		g_bytes_unref (ssid_bytes);

		success = TRUE;
cleanup_olpc:
		g_free (ssid_ask);
		g_free (channel);
		g_free (dhcp_anycast);
		if (!success)
			return FALSE;

	} else if (!strcmp (con_type, NM_SETTING_GENERIC_SETTING_NAME)) {
		/* Add 'generic' setting */
		s_generic = (NMSettingGeneric *) nm_setting_generic_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_generic));
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

		NMIPAddress *ip4addr = NULL, *ip6addr = NULL;
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
				ip4addr = nmc_parse_and_build_address (AF_INET, ip4, error);
				if (!ip4addr) {
					g_prefix_error (error, _("Error: "));
					return FALSE;
				}
				add_ip4_address_to_connection (ip4addr, connection);
			}

			/* coverity[dead_error_begin] */
			if (gw4) {
				NMSettingIPConfig *s_ip = nm_connection_get_setting_ip4_config (connection);

				if (!s_ip) {
					g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
					             _("Error: IPv4 gateway specified without IPv4 addresses"));
					return FALSE;
				} else if (nm_setting_ip_config_get_gateway (s_ip)) {
					g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
					             _("Error: multiple IPv4 gateways specified"));
					return FALSE;
				} else if (!nm_utils_ipaddr_valid (AF_INET, gw4)) {
					g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
					             _("Error: Invalid IPv4 gateway '%s'"),
					             gw4);
				}

				g_object_set (s_ip,
				              NM_SETTING_IP_CONFIG_GATEWAY, gw4,
				              NULL);
			}

			/* coverity[dead_error_begin] */
			if (ip6) {
				ip6addr = nmc_parse_and_build_address (AF_INET6, ip6, error);
				if (!ip6addr) {
					g_prefix_error (error, _("Error: "));
					return FALSE;
				}
				add_ip6_address_to_connection (ip6addr, connection);
			}

			/* coverity[dead_error_begin] */
			if (gw6) {
				NMSettingIPConfig *s_ip = nm_connection_get_setting_ip6_config (connection);

				if (!s_ip) {
					g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
					             _("Error: IPv6 gateway specified without IPv6 addresses"));
					return FALSE;
				} else if (nm_setting_ip_config_get_gateway (s_ip)) {
					g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
					             _("Error: multiple IPv6 gateways specified"));
					return FALSE;
				} else if (!nm_utils_ipaddr_valid (AF_INET, gw6)) {
					g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
					             _("Error: Invalid IPv6 gateway '%s'"),
					             gw6);
				}

				g_object_set (s_ip,
				              NM_SETTING_IP_CONFIG_GATEWAY, gw6,
				              NULL);
			}
		}

		/* Ask for addresses if '--ask' is specified. */
		if (ask)
			do_questionnaire_ip (connection);
	}

	return TRUE;
}

static char *
unique_connection_name (const GPtrArray *connections, const char *try_name)
{
	NMConnection *connection;
	const char *name;
	char *new_name;
	unsigned int num = 1;
	int i = 0;

	new_name = g_strdup (try_name);
	while (i < connections->len) {
		connection = NM_CONNECTION (connections->pdata[i]);

		name = nm_connection_get_id (connection);
		if (g_strcmp0 (new_name, name) == 0) {
			g_free (new_name);
			new_name = g_strdup_printf ("%s-%d", try_name, num++);
			i = 0;
		} else
			i++;
	}
	return new_name;
}

typedef struct {
	NmCli *nmc;
	char *con_name;
} AddConnectionInfo;

static void
add_connection_cb (GObject *client,
                   GAsyncResult *result,
                   gpointer user_data)
{
	AddConnectionInfo *info = (AddConnectionInfo *) user_data;
	NmCli *nmc = info->nmc;
	NMRemoteConnection *connection;
	GError *error = NULL;

	connection = nm_client_add_connection_finish (NM_CLIENT (client), result, &error);
	if (error) {
		g_string_printf (nmc->return_text,
		                 _("Error: Failed to add '%s' connection: %s"),
		                 info->con_name, error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
	} else {
		g_print (_("Connection '%s' (%s) successfully added.\n"),
		         nm_connection_get_id (NM_CONNECTION (connection)),
		         nm_connection_get_uuid (NM_CONNECTION (connection)));
		g_object_unref (connection);
	}

	g_free (info->con_name);
	g_free (info);
	quit ();
}

static void
add_new_connection (gboolean persistent,
                    NMClient *client,
                    NMConnection *connection,
                    GAsyncReadyCallback callback,
                    gpointer user_data)
{
	nm_client_add_connection_async (client, connection, persistent,
	                                NULL, callback, user_data);
}

static void
update_connection (gboolean persistent,
                   NMRemoteConnection *connection,
                   GAsyncReadyCallback callback,
                   gpointer user_data)
{
	nm_remote_connection_commit_changes_async (connection, persistent,
	                                           NULL, callback, user_data);
}

static char *
gen_func_vpn_types (const char *text, int state)
{
	return nmc_rl_gen_func_basic (text, state, nmc_known_vpns);
}

static char *
gen_func_bool_values_l10n (const char *text, int state)
{
	const char *words[] = { WORD_LOC_YES, WORD_LOC_NO, NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_func_wifi_mode (const char *text, int state)
{
	const char *words[] = { "infrastructure", "ap", "adhoc", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_func_ib_type (const char *text, int state)
{
	const char *words[] = { "datagram", "connected", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_func_bt_type (const char *text, int state)
{
	const char *words[] = { "panu", "dun-gsm", "dun-cdma", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_func_bond_mode (const char *text, int state)
{
	const char *words[] = { "balance-rr", "active-backup", "balance-xor", "broadcast",
	                        "802.3ad", "balance-tlb", "balance-alb", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}
static char *
gen_func_bond_mon_mode (const char *text, int state)
{
	const char *words[] = { "miimon", "arp", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_func_master_ifnames (const char *text, int state)
{
	int i;
	GPtrArray *ifnames;
	char *ret;
	NMConnection *con;
	NMSettingConnection *s_con;
	const char *con_type, *ifname;

	if (!nm_cli.connections)
		return NULL;

	/* Disable appending space after completion */
	rl_completion_append_character = '\0';

	ifnames = g_ptr_array_sized_new (20);
	for (i = 0; i < nm_cli.connections->len; i++) {
		con = NM_CONNECTION (nm_cli.connections->pdata[i]);
		s_con = nm_connection_get_setting_connection (con);
		g_assert (s_con);
		con_type = nm_setting_connection_get_connection_type (s_con);
		if (g_strcmp0 (con_type, nmc_tab_completion.con_type) != 0)
			continue;
		ifname = nm_connection_get_interface_name (con);
		g_ptr_array_add (ifnames, (gpointer) ifname);
	}
	g_ptr_array_add (ifnames, (gpointer) NULL);

	ret = nmc_rl_gen_func_basic (text, state, (const char **) ifnames->pdata);

	g_ptr_array_free (ifnames, TRUE);
	return ret;
}

static gboolean
is_single_word (const char* line)
{
	size_t n1, n2, n3;

	n1 = strspn  (line,    " \t");
	n2 = strcspn (line+n1, " \t\0") + n1;
	n3 = strspn  (line+n2, " \t");

	if (n3 == 0)
		return TRUE;
	else
		return FALSE;
}

static char **
nmcli_con_add_tab_completion (const char *text, int start, int end)
{
	char **match_array = NULL;
	rl_compentry_func_t *generator_func = NULL;

	/* Disable readline's default filename completion */
	rl_attempted_completion_over = 1;

	/* Restore standard append character to space */
	rl_completion_append_character = ' ';

	if (!is_single_word (rl_line_buffer))
		return NULL;

	if (g_strcmp0 (rl_prompt, PROMPT_CON_TYPE) == 0)
		generator_func = gen_connection_types;
	else if (g_strcmp0 (rl_prompt, PROMPT_VPN_TYPE) == 0)
		generator_func = gen_func_vpn_types;
	else if (   g_strcmp0 (rl_prompt, PROMPT_BOND_MASTER) == 0
	         || g_strcmp0 (rl_prompt, PROMPT_TEAM_MASTER) == 0
	         || g_strcmp0 (rl_prompt, PROMPT_BRIDGE_MASTER) == 0)
		generator_func = gen_func_master_ifnames;
	else if (   g_str_has_suffix (rl_prompt, prompt_yes_no (TRUE, NULL))
	         || g_str_has_suffix (rl_prompt, prompt_yes_no (TRUE, ":"))
	         || g_str_has_suffix (rl_prompt, prompt_yes_no (FALSE, NULL))
	         || g_str_has_suffix (rl_prompt, prompt_yes_no (FALSE, ":")))
		generator_func = gen_func_bool_values_l10n;
	else if (g_str_has_suffix (rl_prompt, PROMPT_WIFI_MODE))
		generator_func = gen_func_wifi_mode;
	else if (g_str_has_suffix (rl_prompt, PROMPT_IB_MODE))
		generator_func = gen_func_ib_type;
	else if (g_str_has_suffix (rl_prompt, PROMPT_BT_TYPE))
		generator_func = gen_func_bt_type;
	else if (g_str_has_prefix (rl_prompt, PROMPT_BOND_MODE))
		generator_func = gen_func_bond_mode;
	else if (g_str_has_suffix (rl_prompt, PROMPT_BOND_MON_MODE))
		generator_func = gen_func_bond_mon_mode;

	if (generator_func)
		match_array = rl_completion_matches (text, generator_func);

	return match_array;
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
	const char *save = NULL;
	gboolean save_bool = TRUE;
	AddConnectionInfo *info = NULL;
	const char *setting_name;
	GError *error = NULL;
	nmc_arg_t exp_args[] = { {"type",        TRUE, &type,        !nmc->ask},
	                         {"con-name",    TRUE, &con_name,    FALSE},
	                         {"autoconnect", TRUE, &autoconnect, FALSE},
	                         {"ifname",      TRUE, &ifname,      FALSE},
	                         {"save",        TRUE, &save,        FALSE},
	                         {NULL} };

	rl_attempted_completion_function = (rl_completion_func_t *) nmcli_con_add_tab_completion;

	nmc->return_value = NMC_RESULT_SUCCESS;

	if (!nmc_parse_args (exp_args, FALSE, &argc, &argv, &error)) {
		g_string_assign (nmc->return_text, error->message);
		nmc->return_value = error->code;
		g_clear_error (&error);
		goto error;
	}

	if (!type && nmc->ask) {
		char *types_tmp = get_valid_options_string (nmc_valid_connection_types);
		g_print ("Valid types: [%s]\n", types_tmp);
		type = type_ask = nmc_readline (PROMPT_CON_TYPE);
		g_free (types_tmp);
	}
	if (!type) {
		g_string_printf (nmc->return_text, _("Error: 'type' argument is required."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}
	if (type_ask)
		type = g_strstrip (type_ask);

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
	if (save) {
		GError *tmp_err = NULL;
		if (!nmc_string_to_bool (save, &save_bool, &tmp_err)) {
			g_string_printf (nmc->return_text, _("Error: 'save': %s."),
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

	if (!ifname && ifname_mandatory && nmc->ask) {
		ifname = ifname_ask = nmc_readline (_("Interface name [*]: "));
		if (!ifname)
			ifname = ifname_ask = g_strdup ("*");
	}
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
	connection = nm_simple_connection_new ();

	/* Build up the 'connection' setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	uuid = nm_utils_uuid_generate ();
	if (con_name)
		default_name = g_strdup (con_name);
	else {
		char *try_name = ifname ?
		                     g_strdup_printf ("%s-%s", get_name_alias (setting_name, nmc_valid_connection_types), ifname)
		                   : g_strdup (get_name_alias (setting_name, nmc_valid_connection_types));
		default_name = unique_connection_name (nmc->connections, try_name);
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
	                                  nmc->connections,
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
	add_new_connection (save_bool,
	                    nmc->client,
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
/* Functions for readline TAB completion in editor */

static void
uuid_display_hook (char **array, int len, int max_len)
{
	NMConnection *con;
	int i, max = 0;
	char *tmp;
	const char *id;
	for (i = 1; i <= len; i++) {
		con = nmc_find_connection (nmc_tab_completion.nmc->connections, "uuid", array[i], NULL);
		id = con ? nm_connection_get_id (con) : NULL;
		if (id) {
			tmp = g_strdup_printf ("%s (%s)", array[i], id);
			g_free (array[i]);
			array[i] = tmp;
			if (max < strlen (id))
				max = strlen (id);
		}
	}
	rl_display_match_list (array, len, max_len + max + 3);
	rl_forced_update_display ();
}

static char *
gen_nmcli_cmds_menu (const char *text, int state)
{
	const char *words[] = { "goto", "set", "remove", "describe", "print", "verify",
	                        "save", "activate", "back", "help", "quit", "nmcli",
	                        NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_nmcli_cmds_submenu (const char *text, int state)
{
	const char *words[] = { "set", "add", "change", "remove", "describe",
	                        "print", "back", "help", "quit",
	                        NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_cmd_nmcli (const char *text, int state)
{
	const char *words[] = { "status-line", "save-confirmation", "show-secrets", "prompt-color", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_cmd_nmcli_prompt_color (const char *text, int state)
{
	const char *words[] = { "0", "1", "2", "3", "4", "5", "6", "7", "8", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_func_bool_values (const char *text, int state)
{
	const char *words[] = { "yes", "no", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_cmd_verify0 (const char *text, int state)
{
	const char *words[] = { "all", "fix", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_cmd_print0 (const char *text, int state)
{
	static char **words = NULL;
	char *ret = NULL;

	if (!state) {
		GVariant *settings;
		GVariantIter iter;
		const char *setting_name;
		int i = 0;

		settings = nm_connection_to_dbus (nmc_tab_completion.connection, NM_CONNECTION_SERIALIZE_NO_SECRETS);
		words = g_new (char *, g_variant_n_children (settings) + 2);
		g_variant_iter_init (&iter, settings);
		while (g_variant_iter_next (&iter, "{&s@a{sv}}", &setting_name, NULL))
			words [i++] = g_strdup (setting_name);
		words[i++] = g_strdup ("all");
		words[i] = NULL;
		g_variant_unref (settings);
	}

	if (words) {
		ret = nmc_rl_gen_func_basic (text, state, (const char **) words);
		if (ret == NULL) {
			g_strfreev (words);
			words = NULL;
		}
	}
	return ret;
}

static char *
gen_cmd_print2 (const char *text, int state)
{
	const char *words[] = { "setting", "connection", "all", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_cmd_save (const char *text, int state)
{
	const char *words[] = { "persistent", "temporary", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_connection_types (const char *text, int state)
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
gen_setting_names (const char *text, int state)
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
gen_property_names (const char *text, int state)
{
	NMSetting *setting = NULL;
	char **valid_props = NULL;
	char *ret = NULL;
	const char *line = rl_line_buffer;
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
		ret = nmc_rl_gen_func_basic (text, state, (const char **) valid_props);
	}

	g_strfreev (strv);
	g_strfreev (valid_props);
	if (setting)
		g_object_unref (setting);
	return ret;
}

static char *
gen_compat_devices (const char *text, int state)
{
	int i, j = 0;
	const GPtrArray *devices;
	const char **compatible_devices;
	char *ret;

	devices = nm_client_get_devices (nmc_tab_completion.nmc->client);
	if (devices->len == 0)
		return NULL;

	compatible_devices = g_new (const char *, devices->len + 1);
	for (i = 0; i < devices->len; i++) {
		NMDevice *dev = g_ptr_array_index (devices, i);
		const char *ifname = nm_device_get_iface (dev);
		NMDevice *device = NULL;
		const char *spec_object = NULL;

		if (find_device_for_connection (nmc_tab_completion.nmc, nmc_tab_completion.connection,
		                                ifname, NULL, NULL, &device, &spec_object, NULL)) {
			compatible_devices[j++] = ifname;
		}
	}
	compatible_devices[j] = NULL;

	ret = nmc_rl_gen_func_basic (text, state, compatible_devices);

	g_free (compatible_devices);
	return ret;
}

static char *
gen_vpn_uuids (const char *text, int state)
{
	const GPtrArray *connections = nmc_tab_completion.nmc->connections;
	int c, u = 0;
	const char **uuids;
	char *ret;

	if (connections->len < 1)
		return NULL;

	uuids = g_new (const char *, connections->len + 1);
	for (c = 0; c < connections->len; c++) {
		NMConnection *connection = NM_CONNECTION (connections->pdata[c]);
		const char *type = nm_connection_get_connection_type (connection);

		if (g_strcmp0 (type, NM_SETTING_VPN_SETTING_NAME) == 0)
			uuids[u++] = nm_connection_get_uuid (connection);
	}
	uuids[u] = NULL;

	ret = nmc_rl_gen_func_basic (text, state, uuids);

	g_free (uuids);
	return ret;
}

static rl_compentry_func_t *
get_gen_func_cmd_nmcli (const char *str)
{
	if (!str)
		return NULL;
	if (matches (str, "status-line") == 0)
		return gen_func_bool_values;
	if (matches (str, "save-confirmation") == 0)
		return gen_func_bool_values;
	if (matches (str, "show-secrets") == 0)
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
 * extract_setting_and_property:
 * prompt: (in) (allow-none): prompt string, or NULL
 * line: (in) (allow-none): line, or NULL
 * setting: (out) (transfer full) (array zero-terminated=1):
 *   return location for setting name
 * property: (out) (transfer full) (array zero-terminated=1):
 *   return location for property name
 *
 * Extract setting and property names from prompt and/or line.
 */
static void
extract_setting_and_property (const char *prompt, const char *line,
                              char **setting, char **property)
{
	char *prop = NULL;
	char *sett = NULL;

	if (prompt) {
		/* prompt looks like this:
		  "nmcli 802-1x>" or "nmcli 802-1x.pac-file>" */
		const char *p1, *p2, *dot;
		size_t num1, num2;
		p1 = strchr (prompt, ' ');
		if (p1) {
			dot = strchr (++p1, '.');
			if (dot) {
				p2 = dot + 1;
				num1 = strcspn (p1, ".");
				num2 = strcspn (p2, ">");
				sett = num1 > 0 ? g_strndup (p1, num1) : NULL;
				prop = num2 > 0 ? g_strndup (p2, num2) : NULL;
			} else {
				num1 = strcspn (p1, ">");
				sett = num1 > 0 ? g_strndup (p1, num1) : NULL;
			}
		}
	}

	if (line) {
		/* line looks like this:
		  " set 802-1x.pac-file ..." or " set pac-file ..." */
		const char *p1, *p2, *dot;
		size_t n1, n2, n3, n4;
		size_t num1, num2, len;
		n1 = strspn  (line,    " \t");         /* white-space */
		n2 = strcspn (line+n1, " \t\0") + n1;  /* command */
		n3 = strspn  (line+n2, " \t")   + n2;  /* white-space */
		n4 = strcspn (line+n3, " \t\0") + n3;  /* setting/property */
		p1 = line + n3;
		len = n4 - n3;

		dot = strchr (p1, '.');
		if (dot && dot < p1 + len) {
			p2 = dot + 1;
			num1 = strcspn (p1, ".");
			num2 = len > num1 + 1 ? len - num1 - 1 : 0;
			sett = num1 > 0 ? g_strndup (p1, num1) : sett;
			prop = num2 > 0 ? g_strndup (p2, num2) : prop;
		} else {
			if (!prop)
				prop = len > 0 ? g_strndup (p1, len) : NULL;
		}
	}

	if (setting)
		*setting = sett;
	else
		g_free (sett);
	if (property)
		*property = prop;
	else
		g_free (prop);
}

static gboolean
_get_and_check_property (const char *prompt,
                         const char *line,
                         const char **array,
                         const char **array_multi,
                         gboolean *multi)
{
	char *prop;
	gboolean found = FALSE;

	extract_setting_and_property (prompt, line, NULL, &prop);
	if (prop) {
		if (array)
			found = !!nmc_string_is_valid (prop, array, NULL);
		if (array_multi && multi)
			*multi = !!nmc_string_is_valid (prop, array_multi, NULL);
		g_free (prop);
	}
	return found;
}

static gboolean
should_complete_files (const char *prompt, const char *line)
{
	const char *file_properties[] = {
		/* '802-1x' properties */
		"ca-cert",
		"ca-path",
		"client-cert",
		"pac-file",
		"phase2-ca-cert",
		"phase2-ca-path",
		"phase2-client-cert",
		"private-key",
		"phase2-private-key",
		/* 'team' and 'team-port' properties */
		"config",
		NULL
	};
	return _get_and_check_property (prompt, line, file_properties, NULL, NULL);
}

static gboolean
should_complete_vpn_uuids (const char *prompt, const char *line)
{
	const char *uuid_properties[] = {
		/* 'connection' properties */
		"secondaries",
		NULL
	};
	return _get_and_check_property (prompt, line, uuid_properties, NULL, NULL);
}

static char *is_property_valid (NMSetting *setting, const char *property, GError **error);
static const char **
get_allowed_property_values (void)
{
	const NameItem *valid_settings_arr;
	const char *setting_name;
	NMSetting *setting = NULL;
	char *property = NULL;
	char *sett = NULL, *prop = NULL;
	const char **avals = NULL;

	extract_setting_and_property (rl_prompt, rl_line_buffer, &sett, &prop);
	if (sett) {
		valid_settings_arr = get_valid_settings_array (nmc_tab_completion.con_type);
		setting_name = check_valid_name (sett, valid_settings_arr, NULL);
		setting = nmc_setting_new_for_name (setting_name);
	} else
		setting = nmc_tab_completion.setting ? g_object_ref (nmc_tab_completion.setting) : NULL;

	if (setting && prop)
		property = is_property_valid (setting, prop, NULL);
	else
		property = g_strdup (nmc_tab_completion.property);

	if (setting && property)
		avals = nmc_setting_get_property_allowed_values (setting, property);

	g_free (sett);
	g_free (prop);
	if (setting)
		g_object_unref (setting);
	g_free (property);
	return avals;
}

static gboolean
should_complete_property_values (const char *prompt, const char *line, gboolean *multi)
{
	/* properties allowing multiple values */
	const char *multi_props[] = {
		/* '802-1x' properties */
		NM_SETTING_802_1X_EAP,
		/* '802-11-wireless-security' properties */
		NM_SETTING_WIRELESS_SECURITY_PROTO,
		NM_SETTING_WIRELESS_SECURITY_PAIRWISE,
		NM_SETTING_WIRELESS_SECURITY_GROUP,
		/* 'bond' properties */
		NM_SETTING_BOND_OPTIONS,
		/* 'ethernet' properties */
		NM_SETTING_WIRED_S390_OPTIONS,
		NULL
	};
	_get_and_check_property (prompt, line, NULL, multi_props, multi);
	return get_allowed_property_values () != NULL;
}

static char *
gen_property_values (const char *text, int state)
{
	char *ret = NULL;
	const char **avals;

	avals = get_allowed_property_values ();
	if (avals)
		ret = nmc_rl_gen_func_basic (text, state, avals);
	return ret;
}

/* from readline */
extern int rl_complete_with_tilde_expansion;

/*
 * Attempt to complete on the contents of TEXT.  START and END show the
 * region of TEXT that contains the word to complete.  We can use the
 * entire line in case we want to do some simple parsing.  Return the
 * array of matches, or NULL if there aren't any.
 */
static char **
nmcli_editor_tab_completion (const char *text, int start, int end)
{
	char **match_array = NULL;
	const char *line = rl_line_buffer;
	rl_compentry_func_t *generator_func = NULL;
	char *prompt_tmp;
	char *word = NULL;
	size_t n1;
	int num;

	/* Restore standard append character to space */
	rl_completion_append_character = ' ';

	/* Restore standard function for displaying matches */
	rl_completion_display_matches_hook = NULL;

	/* Disable default filename completion */
	rl_attempted_completion_over = 1;

	/* Enable tilde expansion when filenames are completed */
	rl_complete_with_tilde_expansion = 1;

	/* Filter out possible ANSI color escape sequences */
	prompt_tmp = nmc_filter_out_colors ((const char *) rl_prompt);

	/* Find the first non-space character */
	n1 = strspn (line, " \t");

	/* Choose the right generator function */
	if (strcmp (prompt_tmp, EDITOR_PROMPT_CON_TYPE) == 0)
		generator_func = gen_connection_types;
	else if (strcmp (prompt_tmp, EDITOR_PROMPT_SETTING) == 0)
		generator_func = gen_setting_names;
	else if (strcmp (prompt_tmp, EDITOR_PROMPT_PROPERTY) == 0)
		generator_func = gen_property_names;
	else if (   g_str_has_suffix (rl_prompt, prompt_yes_no (TRUE, NULL))
	         || g_str_has_suffix (rl_prompt, prompt_yes_no (FALSE, NULL)))
		generator_func = gen_func_bool_values_l10n;
	else if (g_str_has_prefix (prompt_tmp, "nmcli")) {
		if (!strchr (prompt_tmp, '.')) {
			int level = g_str_has_prefix (prompt_tmp, "nmcli>") ? 0 : 1;
			const char *dot = strchr (line, '.');
			gboolean multi;

			/* Main menu  - level 0,1 */
			if (start == n1)
				generator_func = gen_nmcli_cmds_menu;
			else {
				if (should_complete_cmd (line, end, "goto", &num, NULL) && num <= 2) {
					if (level == 0 && (!dot || dot >= line + end))
						generator_func = gen_setting_names;
					else
						generator_func = gen_property_names;
				} else if (should_complete_cmd (line, end, "set", &num, NULL)) {
					if (num < 3) {
						if (level == 0 && (!dot || dot >= line + end)) {
							generator_func = gen_setting_names;
							rl_completion_append_character = '.';
						} else
							generator_func = gen_property_names;
					} else if (num >= 3) {
						if (num == 3 && should_complete_files (NULL, line))
							rl_attempted_completion_over = 0;
						else if (should_complete_vpn_uuids (NULL, line)) {
							rl_completion_display_matches_hook = uuid_display_hook;
							generator_func = gen_vpn_uuids;
						} else if (   should_complete_property_values (NULL, line, &multi)
							   && (num == 3 || multi)) {
							generator_func = gen_property_values;
						}
					}
				} else if (  (   should_complete_cmd (line, end, "remove", &num, NULL)
				              || should_complete_cmd (line, end, "describe", &num, NULL))
				           && num <= 2) {
					if (level == 0 && (!dot || dot >= line + end)) {
						generator_func = gen_setting_names;
						rl_completion_append_character = '.';
					} else
						generator_func = gen_property_names;
				} else if (should_complete_cmd (line, end, "nmcli", &num, &word)) {
					if (num < 3)
						generator_func = gen_cmd_nmcli;
					else if (num == 3)
						generator_func = get_gen_func_cmd_nmcli (word);
				} else if (should_complete_cmd (line, end, "print", &num, NULL) && num <= 2) {
					if (level == 0 && (!dot || dot >= line + end))
						generator_func = gen_cmd_print0;
					else
						generator_func = gen_property_names;
				} else if (should_complete_cmd (line, end, "verify", &num, NULL) && num <= 2) {
					generator_func = gen_cmd_verify0;
				} else if (should_complete_cmd (line, end, "activate", &num, NULL) && num <= 2) {
					generator_func = gen_compat_devices;
				} else if (should_complete_cmd (line, end, "save", &num, NULL) && num <= 2) {
					generator_func = gen_cmd_save;
				} else if (should_complete_cmd (line, end, "help", &num, NULL) && num <= 2)
					generator_func = gen_nmcli_cmds_menu;
			}
		} else {
			/* Submenu - level 2 */
			if (start == n1)
				generator_func = gen_nmcli_cmds_submenu;
			else {
				gboolean multi;

				if (   should_complete_cmd (line, end, "add", &num, NULL)
				    || should_complete_cmd (line, end, "set", &num, NULL)) {
					if (num <= 2 && should_complete_files (prompt_tmp, line))
						rl_attempted_completion_over = 0;
					else if (should_complete_vpn_uuids (prompt_tmp, line)) {
						rl_completion_display_matches_hook = uuid_display_hook;
						generator_func = gen_vpn_uuids;
					} else if (   should_complete_property_values (prompt_tmp, NULL, &multi)
						   && (num <= 2 || multi)) {
						generator_func = gen_property_values;
					}
				}
				if (should_complete_cmd (line, end, "print", &num, NULL) && num <= 2)
					generator_func = gen_cmd_print2;
				else if (should_complete_cmd (line, end, "help", &num, NULL) && num <= 2)
					generator_func = gen_nmcli_cmds_submenu;
			}
		}
	}

	if (generator_func)
		match_array = rl_completion_matches (text, generator_func);

	g_free (prompt_tmp);
	g_free (word);
	return match_array;
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

	filename = g_build_filename (g_get_home_dir (), NMCLI_EDITOR_HISTORY, NULL);
	kf = g_key_file_new ();
	if (!g_key_file_load_from_file (kf, filename, G_KEY_FILE_KEEP_COMMENTS, &err)) {
		if (err->code == G_KEY_FILE_ERROR_PARSE)
			g_print ("Warning: %s parse error: %s\n", filename, err->message);
		g_key_file_free (kf);
		g_free (filename);
		return;
	}
	keys = g_key_file_get_keys (kf, uuid, NULL, NULL);
	for (i = 0; keys && keys[i]; i++) {
		line = g_key_file_get_string (kf, uuid, keys[i], NULL);
		if (line && *line)
			add_history (line);
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

	hist = history_list ();
	if (hist) {
		filename = g_build_filename (g_get_home_dir (), NMCLI_EDITOR_HISTORY, NULL);
		kf = g_key_file_new ();
		if (!g_key_file_load_from_file (kf, filename, G_KEY_FILE_KEEP_COMMENTS, &err)) {
			if (   err->code != G_FILE_ERROR_NOENT
			    && err->code != G_KEY_FILE_ERROR_NOT_FOUND) {
				g_print ("Warning: %s parse error: %s\n", filename, err->message);
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

	nmc_connection_profile_details (connection, nmc, nmc->editor_show_secrets);
}

static void
editor_show_setting (NMSetting *setting, NmCli *nmc)
{
	g_print (_("['%s' setting values]\n"),
	         nm_setting_get_name (setting));

	nmc->print_output = NMC_PRINT_NORMAL;
	nmc->multiline_output = TRUE;
	nmc->escape_values = 0;

	/* Remove any previous data */
	nmc_empty_output_fields (nmc);

	setting_details (setting, nmc, NULL, nmc->editor_show_secrets);
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
	g_print ("------------------------------------------------------------------------------\n");
	/* TRANSLATORS: do not translate command names and keywords before ::
	 *              However, you should translate terms enclosed in <>.
	 */
	g_print (_("---[ Main menu ]---\n"
	           "goto     [<setting> | <prop>]        :: go to a setting or property\n"
	           "remove   <setting>[.<prop>] | <prop> :: remove setting or reset property value\n"
	           "set      [<setting>.<prop> <value>]  :: set property value\n"
	           "describe [<setting>.<prop>]          :: describe property\n"
	           "print    [all | <setting>[.<prop>]]  :: print the connection\n"
	           "verify   [all | fix]                 :: verify the connection\n"
	           "save     [persistent|temporary]      :: save the connection\n"
	           "activate [<ifname>] [/<ap>|<nsp>]    :: activate the connection\n"
	           "back                                 :: go one level up (back)\n"
	           "help/?   [<command>]                 :: print this help\n"
	           "nmcli    <conf-option> <value>       :: nmcli configuration\n"
	           "quit                                 :: exit nmcli\n"));
	g_print ("------------------------------------------------------------------------------\n");
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
			g_print (_("goto <setting>[.<prop>] | <prop>  :: enter setting/property for editing\n\n"
			           "This command enters into a setting or property for editing it.\n\n"
			           "Examples: nmcli> goto connection\n"
			           "          nmcli connection> goto secondaries\n"
			           "          nmcli> goto ipv4.addresses\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_REMOVE:
			g_print (_("remove <setting>[.<prop>]  :: remove setting or reset property value\n\n"
			           "This command removes an entire setting from the connection, or if a property\n"
			           "is given, resets that property to the default value.\n\n"
			           "Examples: nmcli> remove wifi-sec\n"
			           "          nmcli> remove eth.mtu\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_SET:
			g_print (_("set [<setting>.<prop> <value>]  :: set property value\n\n"
			           "This command sets property value.\n\n"
			           "Example: nmcli> set con.id My connection\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_DESCRIBE:
			g_print (_("describe [<setting>.<prop>]  :: describe property\n\n"
			           "Shows property description. You can consult nm-settings(5) "
			           "manual page to see all NM settings and properties.\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_PRINT:
			g_print (_("print [all]  :: print setting or connection values\n\n"
			           "Shows current property or the whole connection.\n\n"
			           "Example: nmcli ipv4> print all\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_VERIFY:
			g_print (_("verify [all | fix]  :: verify setting or connection validity\n\n"
			           "Verifies whether the setting or connection is valid and can be saved later.\n"
			           "It indicates invalid values on error. Some errors may be fixed automatically\n"
			           "by 'fix' option.\n\n"
			           "Examples: nmcli> verify\n"
			           "          nmcli> verify fix\n"
			           "          nmcli bond> verify\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_SAVE:
			g_print (_("save [persistent|temporary]  :: save the connection\n\n"
			           "Sends the connection profile to NetworkManager that either will save it\n"
			           "persistently, or will only keep it in memory. 'save' without an argument\n"
			           "means 'save persistent'.\n"
			           "Note that once you save the profile persistently those settings are saved\n"
			           "across reboot or restart. Subsequent changes can also be temporary or\n"
			           "persistent, but any temporary changes will not persist across reboot or\n"
			           "restart. If you want to fully remove the persistent connection, the connection\n"
			           "profile must be deleted.\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_ACTIVATE:
			g_print (_("activate [<ifname>] [/<ap>|<nsp>]  :: activate the connection\n\n"
			           "Activates the connection.\n\n"
			           "Available options:\n"
			           "<ifname>    - device the connection will be activated on\n"
			           "/<ap>|<nsp> - AP (Wi-Fi) or NSP (WiMAX) (prepend with / when <ifname> is not specified)\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_BACK:
			g_print (_("back  :: go to upper menu level\n\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_HELP:
			g_print (_("help/? [<command>]  :: help for the nmcli commands\n\n"));
			break;
		case NMC_EDITOR_MAIN_CMD_NMCLI:
			g_print (_("nmcli [<conf-option> <value>]  :: nmcli configuration\n\n"
			           "Configures nmcli. The following options are available:\n"
			           "status-line yes | no          [default: no]\n"
			           "save-confirmation yes | no    [default: yes]\n"
			           "show-secrets yes | no         [default: no]\n"
			           "prompt-color <color> | <0-8>  [default: 0]\n"
			           "%s"  /* color table description */
			           "\n"
			           "Examples: nmcli> nmcli status-line yes\n"
			           "          nmcli> nmcli save-confirmation no\n"
			           "          nmcli> nmcli prompt-color 3\n"),
			           "  0 = normal\n"
			           "  1 = \33[30mblack\33[0m\n"
			           "  2 = \33[31mred\33[0m\n"
			           "  3 = \33[32mgreen\33[0m\n"
			           "  4 = \33[33myellow\33[0m\n"
			           "  5 = \33[34mblue\33[0m\n"
			           "  6 = \33[35mmagenta\33[0m\n"
			           "  7 = \33[36mcyan\33[0m\n"
			           "  8 = \33[37mwhite\33[0m\n");
			break;
		case NMC_EDITOR_MAIN_CMD_QUIT:
			g_print (_("quit  :: exit nmcli\n\n"
			           "This command exits nmcli. When the connection being edited "
			           "is not saved, the user is asked to confirm the action.\n"));
			break;
		default:
			g_print (_("Unknown command: '%s'\n"), command);
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
	g_print ("------------------------------------------------------------------------------\n");
	/* TRANSLATORS: do not translate command names and keywords before ::
	 *              However, you should translate terms enclosed in <>.
	 */
	g_print (_("---[ Property menu ]---\n"
	           "set      [<value>]               :: set new value\n"
	           "add      [<value>]               :: add new option to the property\n"
	           "change                           :: change current value\n"
	           "remove   [<index> | <option>]    :: delete the value\n"
	           "describe                         :: describe property\n"
	           "print    [setting | connection]  :: print property (setting/connection) value(s)\n"
	           "back                             :: go to upper level\n"
	           "help/?   [<command>]             :: print this help or command description\n"
	           "quit                             :: exit nmcli\n"));
	g_print ("------------------------------------------------------------------------------\n");
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
			g_print (_("set [<value>]  :: set new value\n\n"
			           "This command sets provided <value> to this property\n"));
			break;
		case NMC_EDITOR_SUB_CMD_ADD:
			g_print (_("add [<value>]  :: append new value to the property\n\n"
			           "This command adds provided <value> to this property, if "
			           "the property is of a container type. For single-valued "
			           "properties the property value is replaced (same as 'set').\n"));
			break;
		case NMC_EDITOR_SUB_CMD_CHANGE:
			g_print (_("change  :: change current value\n\n"
			           "Displays current value and allows editing it.\n"));
			break;
		case NMC_EDITOR_SUB_CMD_REMOVE:
			g_print (_("remove [<value>|<index>|<option name>]  :: delete the value\n\n"
			           "Removes the property value. For single-valued properties, this sets the\n"
			           "property back to its default value. For container-type properties, this removes\n"
			           "all the values of that property, or you can specify an argument to remove just\n"
			           "a single item or option. The argument is either a value or index of the item to\n"
			           "remove, or an option name (for properties with named options).\n\n"
			           "Examples: nmcli ipv4.dns> remove 8.8.8.8\n"
			           "          nmcli ipv4.dns> remove 2\n"
			           "          nmcli bond.options> remove downdelay\n\n"));
			break;
		case NMC_EDITOR_SUB_CMD_DESCRIBE:
			g_print (_("describe  :: describe property\n\n"
			           "Shows property description. You can consult nm-settings(5) "
			           "manual page to see all NM settings and properties.\n"));
			break;
		case NMC_EDITOR_SUB_CMD_PRINT:
			g_print (_("print [property|setting|connection]  :: print property (setting, connection) value(s)\n\n"
			           "Shows property value. Providing an argument you can also display "
			           "values for the whole setting or connection.\n"));
			break;
		case NMC_EDITOR_SUB_CMD_BACK:
			g_print (_("back  :: go to upper menu level\n\n"));
			break;
		case NMC_EDITOR_SUB_CMD_HELP:
			g_print (_("help/? [<command>]  :: help for nmcli commands\n\n"));
			break;
		case NMC_EDITOR_SUB_CMD_QUIT:
			g_print (_("quit  :: exit nmcli\n\n"
			           "This command exits nmcli. When the connection being edited "
			           "is not saved, the user is asked to confirm the action.\n"));
			break;
		default:
			g_print (_("Unknown command: '%s'\n"), command);
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
add_connection_editor_cb (GObject *client,
                          GAsyncResult *result,
                          gpointer user_data)
{
	NMRemoteConnection *connection;
	GError *error = NULL;

	connection = nm_client_add_connection_finish (NM_CLIENT (client), result, &error);
	set_info_and_signal_editor_thread (error, NULL);

	g_clear_object (&connection);
	g_clear_error (&error);
}

static void
update_connection_editor_cb (GObject *connection,
                             GAsyncResult *result,
                             gpointer user_data)
{
	GError *error = NULL;

	nm_remote_connection_commit_changes_finish (NM_REMOTE_CONNECTION (connection),
	                                            result, &error);
	set_info_and_signal_editor_thread (error, NULL);
	g_clear_error (&error);
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
		goto finish;

	ac_state = nm_active_connection_get_state (ac);
	dev_state = nm_device_get_state (device);

	nmc_terminal_show_progress (nmc_device_state_to_string (dev_state));

	if (   ac_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED
	    || dev_state == NM_DEVICE_STATE_ACTIVATED) {
		nmc_terminal_erase_line ();
		g_print (_("Connection successfully activated (D-Bus active path: %s)\n"),
		         nm_object_get_path (NM_OBJECT (ac)));
		goto finish; /* we are done */
	} else if (   ac_state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED
	           || dev_state == NM_DEVICE_STATE_FAILED) {
		nmc_terminal_erase_line ();
		g_print (_("Error: Connection activation failed.\n"));
		goto finish; /* we are done */
	}

	return TRUE;

finish:
	if (device)
		g_object_unref (device);
	if (ac)
		g_object_unref (ac);
	return FALSE;
}

static void
activate_connection_editor_cb (GObject *client,
                               GAsyncResult *result,
                               gpointer user_data)
{
	ActivateConnectionInfo *info = (ActivateConnectionInfo *) user_data;
	NMDevice *device = info->device;
	const GPtrArray *ac_devs;
	MonitorACInfo *monitor_ac_info = NULL;
	NMActiveConnection *active;
	GError *error = NULL;

	active = nm_client_activate_connection_finish (NM_CLIENT (client), result, &error);

	if (!error) {
		if (!device) {
			ac_devs = nm_active_connection_get_devices (active);
			device = ac_devs->len > 0 ? g_ptr_array_index (ac_devs, 0) : NULL;
		}
		if (device) {
			monitor_ac_info = g_malloc0 (sizeof (AddConnectionInfo));
			monitor_ac_info->device = g_object_ref (device);
			monitor_ac_info->ac = active;
			monitor_ac_info->monitor_id = g_timeout_add (120, progress_activation_editor_cb, monitor_ac_info);
		} else
			g_object_unref (active);
	}
	set_info_and_signal_editor_thread (error, monitor_ac_info);
	g_clear_error (&error);
}

/*----------------------------------------------------------------------------*/

static void
print_property_description (NMSetting *setting, const char *prop_name)
{
	char *desc;

	desc = nmc_setting_get_property_desc (setting, prop_name);
	g_print ("\n=== [%s] ===\n%s\n", prop_name, desc);
	g_free (desc);
}

static void
print_setting_description (NMSetting *setting)
{
	/* Show description of all properties */
	char **all_props;
	int i;

	all_props = nmc_setting_get_valid_properties (setting);
	g_print (("<<< %s >>>\n"), nm_setting_get_name (setting));
	for (i = 0; all_props && all_props[i]; i++)
		print_property_description (setting, all_props[i]);
	g_strfreev (all_props);
}

static gboolean
connection_remove_setting (NMConnection *connection, NMSetting *setting)
{
	gboolean mandatory;

	g_return_val_if_fail (setting, FALSE);

	mandatory = is_setting_mandatory (connection, setting);
	if (!mandatory) {
		nm_connection_remove_setting (connection, G_OBJECT_TYPE (setting));
		return TRUE;
	}
	g_print (_("Error: setting '%s' is mandatory and cannot be removed.\n"),
	         nm_setting_get_name (setting));
	return FALSE;
}

static void
editor_show_status_line (NMConnection *connection, gboolean dirty, gboolean temp)
{
	NMSettingConnection *s_con;
	const char *con_type, *con_id, *con_uuid;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	con_type = nm_setting_connection_get_connection_type (s_con);
	con_id = nm_connection_get_id (connection);
	con_uuid = nm_connection_get_uuid (connection);

	/* TRANSLATORS: status line in nmcli connection editor */
	g_print (_("[ Type: %s | Name: %s | UUID: %s | Dirty: %s | Temp: %s ]\n"),
	         con_type, con_id, con_uuid,
	         dirty ? _("yes") : _("no"),
	         temp ? _("yes") : _("no"));
}

static gboolean
refresh_remote_connection (GWeakRef *weak, NMRemoteConnection **remote)
{
	gboolean previous;

	g_return_val_if_fail (remote != NULL, FALSE);

	previous = (*remote != NULL);
	if (*remote)
		g_object_unref (*remote);
	*remote = g_weak_ref_get (weak);

	return (previous && !*remote);
}

static gboolean
is_connection_dirty (NMConnection *connection, NMRemoteConnection *remote)
{
	return !nm_connection_compare (connection,
	                               remote ? NM_CONNECTION (remote) : NULL,
	                               NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS |
	                               NM_SETTING_COMPARE_FLAG_IGNORE_TIMESTAMP);
}

static gboolean
confirm_quit (void)
{
	char *answer;
	gboolean want_quit = FALSE;

	answer = nmc_readline (_("The connection is not saved. "
	                         "Do you really want to quit? %s"),
	                       prompt_yes_no (FALSE, NULL));
	answer = answer ? g_strstrip (answer) : NULL;
	if (answer && matches (answer, WORD_LOC_YES) == 0)
		want_quit = TRUE;

	g_free (answer);
	return want_quit;
}

/*
 * Submenu for detailed property editing
 * Return: TRUE - continue;  FALSE - should quit
 */
static gboolean
property_edit_submenu (NmCli *nmc,
                       NMConnection *connection,
                       NMRemoteConnection **rem_con,
                       GWeakRef *rem_con_weak,
                       NMSetting *curr_setting,
                       const char *prop_name)
{
	NmcEditorSubCmd cmdsub;
	gboolean cmd_property_loop = TRUE;
	gboolean should_quit = FALSE;
	char *prop_val_user;
	gboolean set_result;
	GError *tmp_err = NULL;
	char *prompt;
	gboolean dirty;
	GValue prop_g_value = G_VALUE_INIT;
	gboolean temp_changes;
	gboolean removed;

	/* Set global variable for use in TAB completion */
	nmc_tab_completion.property = prop_name;

	prompt = nmc_colorize (nmc->editor_prompt_color, NMC_TERM_FORMAT_NORMAL,
	                       "nmcli %s.%s> ",
	                       nm_setting_get_name (curr_setting), prop_name);

	while (cmd_property_loop) {
		char *cmd_property_user;
		char *cmd_property_arg;

		/* Get the remote connection again, it may have disapeared */
		removed = refresh_remote_connection (rem_con_weak, rem_con);
		if (removed)
			g_print (_("The connection profile has been removed from another client. "
			           "You may type 'save' in the main menu to restore it.\n"));

		/* Connection is dirty? (not saved or differs from the saved) */
		dirty = is_connection_dirty (connection, *rem_con);
		temp_changes = *rem_con ? nm_remote_connection_get_unsaved (*rem_con) : TRUE;
		if (nmc->editor_status_line)
			editor_show_status_line (connection, dirty, temp_changes);

		cmd_property_user = nmc_readline ("%s", prompt);
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
				const char **avals = nmc_setting_get_property_allowed_values (curr_setting, prop_name);
				if (avals) {
					char *avals_str = nmc_util_strv_for_display (avals, FALSE);
					g_print (_("Allowed values for '%s' property: %s\n"),
					         prop_name, avals_str);
					g_free (avals_str);
				}
				prop_val_user = nmc_readline (_("Enter '%s' value: "), prop_name);
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
				g_print (_("Error: failed to set '%s' property: %s\n"), prop_name, tmp_err->message);
				g_clear_error (&tmp_err);
				if (cmdsub == NMC_EDITOR_SUB_CMD_SET) {
					/* Block change signals and restore original value */
					g_signal_handlers_block_matched (curr_setting, G_SIGNAL_MATCH_DATA, 0, 0, NULL, NULL, NULL);
					nmc_property_set_gvalue (curr_setting, prop_name, &prop_g_value);
					g_signal_handlers_unblock_matched (curr_setting, G_SIGNAL_MATCH_DATA, 0, 0, NULL, NULL, NULL);
				}
			}
			if (G_IS_VALUE (&prop_g_value))
				g_value_unset (&prop_g_value);
			break;

		case NMC_EDITOR_SUB_CMD_CHANGE:
			rl_startup_hook = nmc_rl_set_deftext;
			nmc_rl_pre_input_deftext = nmc_setting_get_property_parsable (curr_setting, prop_name, NULL);
			prop_val_user = nmc_readline (_("Edit '%s' value: "), prop_name);

			nmc_property_get_gvalue (curr_setting, prop_name, &prop_g_value);
			nmc_property_set_default_value (curr_setting, prop_name);

			if (!nmc_setting_set_property (curr_setting, prop_name, prop_val_user, &tmp_err)) {
				g_print (_("Error: failed to set '%s' property: %s\n"), prop_name, tmp_err->message);
				g_clear_error (&tmp_err);
				g_signal_handlers_block_matched (curr_setting, G_SIGNAL_MATCH_DATA, 0, 0, NULL, NULL, NULL);
				nmc_property_set_gvalue (curr_setting, prop_name, &prop_g_value);
				g_signal_handlers_unblock_matched (curr_setting, G_SIGNAL_MATCH_DATA, 0, 0, NULL, NULL, NULL);
			}
			g_free (prop_val_user);
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
					g_print (_("Error: %s\n"), tmp_err->message);
					g_clear_error (&tmp_err);
				}
				g_free (option);
			} else {
				if (!nmc_setting_reset_property (curr_setting, prop_name, &tmp_err)) {
					g_print (_("Error: failed to remove value of '%s': %s\n"), prop_name,
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
					g_print (_("Unknown command argument: '%s'\n"), cmd_property_arg);
			} else {
				char *prop_val =  nmc_setting_get_property (curr_setting, prop_name, NULL);
				g_print ("%s: %s\n", prop_name, prop_val);
				g_free (prop_val);
			}
			break;

		case NMC_EDITOR_SUB_CMD_BACK:
			/* Set global variable for use in TAB completion */
			nmc_tab_completion.property = NULL;
			cmd_property_loop = FALSE;
			break;

		case NMC_EDITOR_SUB_CMD_HELP:
			editor_sub_usage (cmd_property_arg);
			break;

		case NMC_EDITOR_SUB_CMD_QUIT:
			if (is_connection_dirty (connection, *rem_con)) {
				if (confirm_quit ()) {
					cmd_property_loop = FALSE;
					should_quit = TRUE;  /* we will quit nmcli */
				}
			} else {
				cmd_property_loop = FALSE;
				should_quit = TRUE;  /* we will quit nmcli */
			}
			break;

		case NMC_EDITOR_SUB_CMD_UNKNOWN:
		default:
			g_print (_("Unknown command: '%s'\n"), cmd_property_user);
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
	ret = g_strdup (prop_name);
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
		g_print (_("Available settings: %s\n"), valid_settings_str);
		setting_name_user = nmc_readline (EDITOR_PROMPT_SETTING);
	} else
		setting_name_user = g_strdup (arg);

	if (setting_name_user)
		g_strstrip (setting_name_user);

	if (!(setting_name = check_valid_name (setting_name_user, valid_settings_arr, &err))) {
		g_print (_("Error: invalid setting name; %s\n"), err->message);
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
		g_print (_("Available properties: %s\n"), valid_props_str);
		prop_name_user = nmc_readline (EDITOR_PROMPT_PROPERTY);
		if (prop_name_user)
			g_strstrip (prop_name_user);
	} else
		prop_name_user = g_strdup (arg);

	if (!(prop_name = nmc_string_is_valid (prop_name_user, valid_props, &tmp_err))) {
		g_print (_("Error: property %s\n"), tmp_err->message);
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
		answer = nmc_readline (_("Saving the connection with 'autoconnect=yes'. "
		                         "That might result in an immediate activation of the connection.\n"
		                         "Do you still want to save? %s"), prompt_yes_no (TRUE, NULL));
		answer = answer ? g_strstrip (answer) : NULL;
		if (!answer || matches (answer, WORD_LOC_YES) == 0)
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
	menu_ctx->main_prompt = nmc_colorize (prompt_color, NMC_TERM_FORMAT_NORMAL, "%s", prompt);
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
	menu_ctx->main_prompt = nmc_colorize (prompt_color, NMC_TERM_FORMAT_NORMAL,
	                                      "nmcli %s> ", setting_name);
	menu_ctx->curr_setting = setting;
	g_strfreev (menu_ctx->valid_props);
	menu_ctx->valid_props = nmc_setting_get_valid_properties (menu_ctx->curr_setting);
	g_free (menu_ctx->valid_props_str);
	menu_ctx->valid_props_str = g_strjoinv (", ", menu_ctx->valid_props);
}

static gboolean
editor_menu_main (NmCli *nmc, NMConnection *connection, const char *connection_type)
{
	NMRemoteConnection *rem_con;
	NMRemoteConnection *con_tmp;
	GWeakRef weak = { { NULL } };
	gboolean removed;
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
	gboolean temp_changes;
	GError *err1 = NULL;
	NmcEditorMenuContext menu_ctx;

	valid_settings_arr = get_valid_settings_array (connection_type);
	valid_settings_str = get_valid_options_string (valid_settings_arr);
	g_print (_("You may edit the following settings: %s\n"), valid_settings_str);

	menu_ctx.level = 0;
	menu_ctx.main_prompt = nmc_colorize (nmc->editor_prompt_color, NMC_TERM_FORMAT_NORMAL,
	                                     BASE_PROMPT);
	menu_ctx.curr_setting = NULL;
	menu_ctx.valid_props = NULL;
	menu_ctx.valid_props_str = NULL;

	/* Get remote connection */
	con_tmp = nm_client_get_connection_by_uuid (nmc->client,
	                                            nm_connection_get_uuid (connection));
	g_weak_ref_init (&weak, con_tmp);
	rem_con = g_weak_ref_get (&weak);

	while (cmd_loop) {
		/* Connection is dirty? (not saved or differs from the saved) */
		dirty = is_connection_dirty (connection, rem_con);
		temp_changes = rem_con ? nm_remote_connection_get_unsaved (rem_con) : TRUE;
		if (nmc->editor_status_line)
			editor_show_status_line (connection, dirty, temp_changes);

		/* Read user input */
		cmd_user = nmc_readline ("%s", menu_ctx.main_prompt);

		/* Get the remote connection again, it may have disapeared */
		removed = refresh_remote_connection (&weak, &rem_con);
		if (removed)
			g_print (_("The connection profile has been removed from another client. "
			           "You may type 'save' to restore it.\n"));

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
					const char **avals;
					GError *tmp_err = NULL;

					prop_name = ask_check_property (cmd_arg,
					                                (const char **) menu_ctx.valid_props,
					                                menu_ctx.valid_props_str);
					if (!prop_name)
						break;

					avals = nmc_setting_get_property_allowed_values (menu_ctx.curr_setting, prop_name);
					if (avals) {
						char *avals_str = nmc_util_strv_for_display (avals, FALSE);
						g_print (_("Allowed values for '%s' property: %s\n"),
						         prop_name, avals_str);
						g_free (avals_str);
					}
					prop_val_user = nmc_readline (_("Enter '%s' value: "), prop_name);

					/* Set property value */
					if (!nmc_setting_set_property (menu_ctx.curr_setting, prop_name, prop_val_user, &tmp_err)) {
						g_print (_("Error: failed to set '%s' property: %s\n"), prop_name, tmp_err->message);
						g_clear_error (&tmp_err);
					}
				} else {
					g_print (_("Error: no setting selected; valid are [%s]\n"), valid_settings_str);
					g_print (_("use 'goto <setting>' first, or 'set <setting>.<property>'\n"));
				}
			} else {
				NMSetting *ss = NULL;
				gboolean created_ss = FALSE;
				char *prop_name;
				GError *tmp_err = NULL;

				if (cmd_arg_s) {
					/* setting provided as "setting.property" */
					ss = is_setting_valid (connection, valid_settings_arr, cmd_arg_s);
					if (!ss) {
						ss = create_setting_by_name (cmd_arg_s, valid_settings_arr);
						if (!ss) {
							g_print (_("Error: invalid setting argument '%s'; valid are [%s]\n"),
							         cmd_arg_s, valid_settings_str);
							break;
						}
						created_ss = TRUE;
					}
				} else {
					if (menu_ctx.curr_setting)
						ss = menu_ctx.curr_setting;
					else {
						g_print (_("Error: missing setting for '%s' property\n"), cmd_arg_p);
						break;
					}
				}

				prop_name = is_property_valid (ss, cmd_arg_p, &tmp_err);
				if (!prop_name) {
					g_print (_("Error: invalid property: %s\n"), tmp_err->message);
					g_clear_error (&tmp_err);
					if (created_ss)
						g_object_unref (ss);
					break;
				}



				/* Ask for value */
				if (!cmd_arg_v) {
					const char **avals = nmc_setting_get_property_allowed_values (ss, prop_name);
					if (avals) {
						char *avals_str = nmc_util_strv_for_display (avals, FALSE);
						g_print (_("Allowed values for '%s' property: %s\n"),
						         prop_name, avals_str);
						g_free (avals_str);
					}
					cmd_arg_v = nmc_readline (_("Enter '%s' value: "), prop_name);
				}

				/* Set property value */
				if (!nmc_setting_set_property (ss, prop_name, cmd_arg_v, &tmp_err)) {
					g_print (_("Error: failed to set '%s' property: %s\n"),
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
						g_print (_("Error: unknown setting '%s'\n"), setting_name);
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
					g_print (_("You may edit the following properties: %s\n"), menu_ctx.valid_props_str);
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
				cmd_loop = property_edit_submenu (nmc,
				                                  connection,
				                                  &rem_con,
				                                  &weak,
				                                  menu_ctx.curr_setting,
				                                  prop_name);
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
						g_print (_("Error: failed to remove value of '%s': %s\n"), prop_name,
						         tmp_err->message);
						g_clear_error (&tmp_err);
					}
				} else
					g_print (_("Error: no argument given; valid are [%s]\n"), valid_settings_str);
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
							g_print (_("Setting '%s' is not present in the connection.\n"), user_s);
						else
							g_print (_("Error: invalid setting argument '%s'; valid are [%s]\n"),
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
							g_print (_("Error: failed to remove value of '%s': %s\n"), prop_name,
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
							/* coverity[copy_paste_error] - suppress Coverity COPY_PASTE_ERROR defect */
							if (ss == menu_ctx.curr_setting) {
								/* If we removed the setting we are in, go up */
								menu_switch_to_level0 (&menu_ctx, BASE_PROMPT, nmc->editor_prompt_color);
								nmc_tab_completion.setting = NULL;  /* for TAB completion */
							}
						} else
							g_print (_("Error: %s properties, nor it is a setting name.\n"),
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
					g_print (_("Error: no setting selected; valid are [%s]\n"), valid_settings_str);
					g_print (_("use 'goto <setting>' first, or 'describe <setting>.<property>'\n"));
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
							g_print (_("Error: invalid setting argument '%s'; valid are [%s]\n"),
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
							g_print (_("Error: invalid property: %s, "
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
					NMSetting *ss = NULL;
					gboolean whole_setting;
					char *user_s;

					/* cmd_arg_s != NULL means argument is "setting.property" */
					whole_setting = !cmd_arg_s && !menu_ctx.curr_setting;
					user_s = whole_setting ? cmd_arg_p : cmd_arg_s ? cmd_arg_s : NULL;
					if (user_s) {
						const char *s_name;
						s_name = check_valid_name (user_s, valid_settings_arr, NULL);
						if (!s_name) {
							g_print (_("Error: unknown setting: '%s'\n"), user_s);
							break;
						}
						ss = nm_connection_get_setting_by_name (connection, s_name);
						if (!ss) {
							g_print (_("Error: '%s' setting not present in the connection\n"), s_name);
							break;
						}
					} else
						ss = menu_ctx.curr_setting;

					if (whole_setting) {
						/* Print the whole setting */
						editor_show_setting (ss, nmc);
					} else {
						GError *err = NULL;
						char *prop_name = is_property_valid (ss, cmd_arg_p, &err);
						if (prop_name) {
							/* Print one property */
							char *prop_val = nmc_setting_get_property (ss, prop_name, NULL);
							g_print ("%s.%s: %s\n", nm_setting_get_name (ss),prop_name , prop_val);
							g_free (prop_val);
						} else {
							/* If the string is not a property, try it as a setting */
							NMSetting *s_tmp;
							s_tmp = is_setting_valid (connection, valid_settings_arr, cmd_arg_p);
							if (s_tmp) {
								/* Print the whole setting */
								editor_show_setting (s_tmp, nmc);
							} else
								g_print (_("Error: invalid property: %s%s\n"),
								         err->message,
								         cmd_arg_s ? "" : _(", neither a valid setting name"));
							g_clear_error (&err);
						}
						g_free (prop_name);
					}
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
			if (cmd_arg && strcmp (cmd_arg, "all") && strcmp (cmd_arg, "fix")) {
				g_print (_("Invalid verify option: %s\n"), cmd_arg);
				break;
			}

			if (   menu_ctx.curr_setting
			    && (!cmd_arg || strcmp (cmd_arg, "all") != 0)) {
				GError *tmp_err = NULL;
				(void) nm_setting_verify (menu_ctx.curr_setting, NULL, &tmp_err);
				g_print (_("Verify setting '%s': %s\n"),
				         nm_setting_get_name (menu_ctx.curr_setting),
				         tmp_err ? tmp_err->message : "OK");
				g_clear_error (&tmp_err);
			} else {
				GError *tmp_err = NULL;
				gboolean valid, modified;
				gboolean fixed = TRUE;

				valid = nm_connection_verify (connection, &tmp_err);
				if (!valid && (g_strcmp0 (cmd_arg, "fix") == 0)) {
					/* Try to fix normalizable errors */
					g_clear_error (&tmp_err);
					fixed = nm_connection_normalize (connection, NULL, &modified, &tmp_err);
				}
				g_print (_("Verify connection: %s\n"),
				         tmp_err ? tmp_err->message : "OK");
				if (!fixed)
					g_print (_("The error cannot be fixed automatically.\n"));
				g_clear_error (&tmp_err);
			}
			break;

		case NMC_EDITOR_MAIN_CMD_SAVE:
			/* Save the connection */
			if (nm_connection_verify (connection, &err1)) {
				gboolean persistent = TRUE;

				/* parse argument */
				if (cmd_arg) {
					if (matches (cmd_arg, "temporary") == 0)
						persistent = FALSE;
					else if (matches (cmd_arg, "persistent") == 0)
						persistent = TRUE;
					else {
						g_print (_("Error: invalid argument '%s'\n"), cmd_arg);
						break;
					}
				}

				/* Ask for save confirmation if the connection changes to autoconnect=yes */
				if (nmc->editor_save_confirmation)
					if (!confirm_connection_saving (connection, NM_CONNECTION (rem_con)))
						break;

				if (!rem_con) {
					/* Tell the settings service to add the new connection */
					info = g_malloc0 (sizeof (AddConnectionInfo));
					info->nmc = nmc;
					info->con_name = g_strdup (nm_connection_get_id (connection));
					add_new_connection (persistent,
					                    nmc->client,
					                    connection,
					                    add_connection_editor_cb,
					                    info);
				} else {
					/* Save/update already saved (existing) connection */
					nm_connection_replace_settings_from_connection (NM_CONNECTION (rem_con),
					                                                connection);
					update_connection (persistent, rem_con, update_connection_editor_cb, NULL);
				}

				g_mutex_lock (&nmc_editor_mutex);
				//FIXME: add also a timeout for cases the callback is not called
				while (!nmc_editor_cb_called)
					g_cond_wait (&nmc_editor_cond, &nmc_editor_mutex);

				if (nmc_editor_error) {
					g_print (_("Error: Failed to save '%s' (%s) connection: %s\n"),
					         nm_connection_get_id (connection),
					         nm_connection_get_uuid (connection),
					         nmc_editor_error->message);
					g_error_free (nmc_editor_error);
				} else {
					g_print (!rem_con ?
					         _("Connection '%s' (%s) successfully saved.\n") :
					         _("Connection '%s' (%s) successfully updated.\n"),
					         nm_connection_get_id (connection),
					         nm_connection_get_uuid (connection));

					con_tmp = nm_client_get_connection_by_uuid (nmc->client,
					                                            nm_connection_get_uuid (connection));
					g_weak_ref_set (&weak, con_tmp);
					refresh_remote_connection (&weak, &rem_con);

					/* Replace local connection with the remote one to be sure they are equal.
					 * This mitigates problems with plugins not preserving some properties or
					 * adding ipv{4,6} settings when not present.
					 */
					if (con_tmp) {
						char *s_name = NULL;
						if (menu_ctx.curr_setting)
							s_name = g_strdup (nm_setting_get_name (menu_ctx.curr_setting));

						/* Update settings in the local connection */
						nm_connection_replace_settings_from_connection (connection,
						                                                NM_CONNECTION (con_tmp));

						/* Also update setting for menu context and TAB-completion */
						menu_ctx.curr_setting = s_name ? nm_connection_get_setting_by_name (connection, s_name) : NULL;
						nmc_tab_completion.setting = menu_ctx.curr_setting;
						g_free (s_name);
					}
				}

				nmc_editor_cb_called = FALSE;
				nmc_editor_error = NULL;
				g_mutex_unlock (&nmc_editor_mutex);
			} else {
				g_print (_("Error: connection verification failed: %s\n"),
				         err1 ? err1->message : _("(unknown error)"));
				g_print (_("You may try running 'verify fix' to fix errors.\n"));
			}

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

			if (is_connection_dirty (connection, rem_con)) {
				g_print (_("Error: connection is not saved. Type 'save' first.\n"));
				break;
			}
			if (!nm_connection_verify (NM_CONNECTION (rem_con), &tmp_err)) {
				g_print (_("Error: connection is not valid: %s\n"), tmp_err->message);
				g_clear_error (&tmp_err);
				break;
			}

			nmc->nowait_flag = FALSE;
			nmc->should_wait = TRUE;
			nmc->print_output = NMC_PRINT_PRETTY;
			if (!nmc_activate_connection (nmc, NM_CONNECTION (rem_con), ifname, ap_nsp, ap_nsp, NULL,
			                              activate_connection_editor_cb, &tmp_err)) {
				g_print (_("Error: Cannot activate connection: %s.\n"), tmp_err->message);
				g_clear_error (&tmp_err);
				break;
			}

			g_mutex_lock (&nmc_editor_mutex);
			while (!nmc_editor_cb_called)
				g_cond_wait (&nmc_editor_cond, &nmc_editor_mutex);

			if (nmc_editor_error) {
				g_print (_("Error: Failed to activate '%s' (%s) connection: %s\n"),
				         nm_connection_get_id (connection),
				         nm_connection_get_uuid (connection),
				         nmc_editor_error->message);
				g_error_free (nmc_editor_error);
			} else {
				g_print (_("Monitoring connection activation (press any key to continue)\n"));
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
					g_print (_("Error: status-line: %s\n"), tmp_err->message);
					g_clear_error (&tmp_err);
				} else
					nmc->editor_status_line = bb;
			} else if (cmd_arg_p && matches (cmd_arg_p, "save-confirmation") == 0) {
				GError *tmp_err = NULL;
				gboolean bb;
				if (!nmc_string_to_bool (cmd_arg_v ? g_strstrip (cmd_arg_v) : "", &bb, &tmp_err)) {
					g_print (_("Error: save-confirmation: %s\n"), tmp_err->message);
					g_clear_error (&tmp_err);
				} else
					nmc->editor_save_confirmation = bb;
			} else if (cmd_arg_p && matches (cmd_arg_p, "show-secrets") == 0) {
				GError *tmp_err = NULL;
				gboolean bb;
				if (!nmc_string_to_bool (cmd_arg_v ? g_strstrip (cmd_arg_v) : "", &bb, &tmp_err)) {
					g_print (_("Error: show-secrets: %s\n"), tmp_err->message);
					g_clear_error (&tmp_err);
				} else
					nmc->editor_show_secrets = bb;
			} else if (cmd_arg_p && matches (cmd_arg_p, "prompt-color") == 0) {
				GError *tmp_err = NULL;
				NmcTermColor color;
				color = nmc_term_color_parse_string (cmd_arg_v ? g_strstrip (cmd_arg_v) : " ", &tmp_err);
				if (tmp_err) {
					g_print (_("Error: bad color: %s\n"), tmp_err->message);
					g_clear_error (&tmp_err);
				} else {
					nmc->editor_prompt_color = color;
					g_free (menu_ctx.main_prompt);
					if (menu_ctx.level == 0)
						menu_ctx.main_prompt = nmc_colorize (nmc->editor_prompt_color, NMC_TERM_FORMAT_NORMAL,
						                                     BASE_PROMPT);
					else
						menu_ctx.main_prompt = nmc_colorize (nmc->editor_prompt_color, NMC_TERM_FORMAT_NORMAL,
						                                     "nmcli %s> ",
						                                     nm_setting_get_name (menu_ctx.curr_setting));
				}
			} else if (!cmd_arg_p) {
				g_print (_("Current nmcli configuration:\n"));
				g_print ("status-line: %s\n"
				         "save-confirmation: %s\n"
				         "show-secrets: %s\n"
				         "prompt-color: %d\n",
				         nmc->editor_status_line ? "yes" : "no",
				         nmc->editor_save_confirmation ? "yes" : "no",
				         nmc->editor_show_secrets ? "yes" : "no",
				         nmc->editor_prompt_color);
			} else
				g_print (_("Invalid configuration option '%s'; allowed [%s]\n"),
				         cmd_arg_v ? cmd_arg_v : "", "status-line, save-confirmation, show-secrets, prompt-color");

			break;

		case NMC_EDITOR_MAIN_CMD_QUIT:
			if (is_connection_dirty (connection, rem_con)) {
				if (confirm_quit ())
					cmd_loop = FALSE;  /* quit command loop */
			} else
				cmd_loop = FALSE;  /* quit command loop */
			break;

		case NMC_EDITOR_MAIN_CMD_UNKNOWN:
		default:
			g_print (_("Unknown command: '%s'\n"), cmd_user);
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
	if (rem_con)
		g_object_unref (rem_con);
	g_weak_ref_clear (&weak);

	/* Save history file */
	save_history_cmds (nm_connection_get_uuid (connection));

	return TRUE;
}

static const char *
get_ethernet_device_name (NmCli *nmc)
{
	const GPtrArray *devices;
	int i;

	devices = nm_client_get_devices (nmc->client);
	for (i = 0; i < devices->len; i++) {
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

	nmc_setting_connection_connect_handlers (s_con, connection);

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

		/* Set a sensible bond/team/bridge interface name by default */
		if (g_strcmp0 (con_type, NM_SETTING_BOND_SETTING_NAME) == 0)
			g_object_set (s_con,
			              NM_SETTING_CONNECTION_INTERFACE_NAME, "nm-bond",
			              NULL);
		if (g_strcmp0 (con_type, NM_SETTING_TEAM_SETTING_NAME) == 0)
			g_object_set (s_con,
			              NM_SETTING_CONNECTION_INTERFACE_NAME, "nm-team",
			              NULL);
		if (g_strcmp0 (con_type, NM_SETTING_BRIDGE_SETTING_NAME) == 0)
			g_object_set (s_con,
			              NM_SETTING_CONNECTION_INTERFACE_NAME, "nm-bridge",
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

		/* Wi-Fi */
		if (g_strcmp0 (con_type, NM_SETTING_WIRELESS_SETTING_NAME) == 0) {
			/* For Wi-Fi set mode to "infrastructure". Even though mode == NULL
			 * is regarded as "infrastructure", explicit value makes no doubts.
			 */
			g_object_set (NM_SETTING_WIRELESS (base_setting),
			              NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_INFRA,
			              NULL);

			/* Do custom initialization for wifi setting */
			nmc_setting_custom_init (base_setting);
		}

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
	NMSettingIPConfig *s_ip4, *s_ip6;
	NMSettingWireless *s_wireless;
	NMSettingConnection *s_con;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	s_wireless = nm_connection_get_setting_wireless (connection);
	s_con = nm_connection_get_setting_connection (connection);

	if (s_ip4)
		nmc_setting_ip4_connect_handlers (s_ip4);
	if (s_ip6)
		nmc_setting_ip6_connect_handlers (s_ip6);
	if (s_wireless)
		nmc_setting_wireless_connect_handlers (s_wireless);
	if (s_con)
		nmc_setting_connection_connect_handlers (s_con, connection);
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

	/* Setup some readline completion stuff */
	/* Set a pointer to an alternative function to create matches */
	rl_attempted_completion_function = (rl_completion_func_t *) nmcli_editor_tab_completion;
	/* Use ' ' and '.' as word break characters */
	rl_completer_word_break_characters = ". ";

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

		found_con = nmc_find_connection (nmc->connections, selector, con, NULL);
		if (!found_con) {
			g_string_printf (nmc->return_text, _("Error: Unknown connection '%s'."), con);
			nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
			goto error;
		}

		/* Duplicate the connection and use that so that we need not
		 * differentiate existing vs. new later
		 */
		connection = nm_simple_connection_new_clone (found_con);

		/* Merge secrets into the connection */
		update_secrets_in_connection (NM_REMOTE_CONNECTION (found_con), connection);

		s_con = nm_connection_get_setting_connection (connection);
		g_assert (s_con);
		connection_type = nm_setting_connection_get_connection_type (s_con);

		if (type)
			g_print (_("Warning: editing existing connection '%s'; 'type' argument is ignored\n"),
			         nm_connection_get_id (connection));
		if (con_name)
			g_print (_("Warning: editing existing connection '%s'; 'con-name' argument is ignored\n"),
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
				g_print (_("Valid connection types: %s\n"), tmp_str);
			else
				g_print (_("Error: invalid connection type; %s\n"), err1->message);
			g_clear_error (&err1);

			type_ask = nmc_readline (EDITOR_PROMPT_CON_TYPE);
			type = type_ask = type_ask ? g_strstrip (type_ask) : NULL;
			connection_type = check_valid_name (type_ask, nmc_valid_connection_types, &err1);
			g_free (type_ask);
		}
		g_free (tmp_str);

		/* Create a new connection object */
		connection = nm_simple_connection_new ();

		/* Build up the 'connection' setting */
		s_con = (NMSettingConnection *) nm_setting_connection_new ();
		uuid = nm_utils_uuid_generate ();
		if (con_name)
			default_name = g_strdup (con_name);
		else
			default_name = unique_connection_name (nmc->connections,
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

	/* nmcli runs the editor */
	nmc->in_editor = TRUE;

	g_print ("\n");
	g_print (_("===| nmcli interactive connection editor |==="));
	g_print ("\n\n");
	if (con)
		g_print (_("Editing existing '%s' connection: '%s'"), connection_type, con);
	else
		g_print (_("Adding a new '%s' connection"), connection_type);
	g_print ("\n\n");
	g_print (_("Type 'help' or '?' for available commands."));
	g_print ("\n");
	g_print (_("Type 'describe [<setting>.<prop>]' for detailed property description."));
	g_print ("\n\n");

	/* Set global variables for use in TAB completion */
	nmc_tab_completion.nmc = nmc;
	nmc_tab_completion.con_type = g_strdup (connection_type);
	nmc_tab_completion.connection = connection;

	/* Run menu loop */
	editor_menu_main (nmc, connection, connection_type);

	if (connection)
		g_object_unref (connection);
	g_free (nmc_tab_completion.con_type);

	nmc->should_wait = TRUE;
	return nmc->return_value;

error:
	g_assert (!connection);
	g_free (type_ask);

	nmc->should_wait = FALSE;
	return nmc->return_value;
}


static void
modify_connection_cb (GObject *connection,
                      GAsyncResult *result,
                      gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;
	GError *error = NULL;

	if (!nm_remote_connection_commit_changes_finish (NM_REMOTE_CONNECTION (connection),
	                                                 result, &error)) {
		g_string_printf (nmc->return_text,
		                 _("Error: Failed to modify connection '%s': %s"),
		                 nm_connection_get_id (NM_CONNECTION (connection)),
		                 error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
	} else {
		if (nmc->print_output == NMC_PRINT_PRETTY)
			g_print (_("Connection '%s' (%s) successfully modified.\n"),
			         nm_connection_get_id (NM_CONNECTION (connection)),
			         nm_connection_get_uuid (NM_CONNECTION (connection)));
	}
	quit ();
}

static NMCResultCode
do_connection_modify (NmCli *nmc,
                      gboolean temporary,
                      int argc,
                      char **argv)
{
	NMConnection *connection = NULL;
	NMRemoteConnection *rc = NULL;
	NMSetting *setting;
	NMSettingConnection *s_con;
	const char *con_type;
	const char *name;
	const char *selector = NULL;
	const char *s_dot_p;
	const char *value;
	char **strv = NULL;
	const char *setting_name;
	char *property_name = NULL;
	gboolean append = FALSE;
	gboolean remove = FALSE;
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
	if (!name) {
		g_string_printf (nmc->return_text, _("Error: connection ID is missing."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}
	connection = nmc_find_connection (nmc->connections, selector, name, NULL);
	if (!connection) {
		g_string_printf (nmc->return_text, _("Error: Unknown connection '%s'."), name);
		nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
		goto finish;
	}
	rc = nm_client_get_connection_by_uuid (nmc->client,
	                                       nm_connection_get_uuid (connection));
	if (!rc) {
		g_string_printf (nmc->return_text, _("Error: Unknown connection '%s'."), name);
		nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
		goto finish;
	}
	s_con = nm_connection_get_setting_connection (NM_CONNECTION (rc));
	g_assert (s_con);
	con_type = nm_setting_connection_get_connection_type (s_con);

	if (next_arg (&argc, &argv) != 0) {
		g_string_printf (nmc->return_text, _("Error: <setting>.<property> argument is missing."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}

	/* Go through arguments and set properties */
	while (argc) {
		s_dot_p = *argv;
		next_arg (&argc, &argv);
		value = *argv;
		next_arg (&argc, &argv);

		if (!s_dot_p) {
			g_string_printf (nmc->return_text, _("Error: <setting>.<property> argument is missing."));
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto finish;
		}
		if (!value) {
			g_string_printf (nmc->return_text, _("Error: value for '%s' is missing."), s_dot_p);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto finish;
		}
		/* Empty string will reset the value to default */
		if (value[0] == '\0')
			value = NULL;

		if (s_dot_p[0] == '+') {
			s_dot_p++;
			append = TRUE;
		} else if (s_dot_p[0] == '-') {
			s_dot_p++;
			remove = TRUE;
		}

		strv = g_strsplit (s_dot_p, ".", 2);
		if (g_strv_length (strv) != 2) {
			g_string_printf (nmc->return_text, _("Error: invalid <setting>.<property> '%s'."),
			                 s_dot_p);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto finish;
		}

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

		if (!remove) {
			/* Set/add value */
			if (!append)
				nmc_setting_reset_property (setting, property_name, NULL);
			if (!nmc_setting_set_property (setting, property_name, value, &error)) {
				g_string_printf (nmc->return_text, _("Error: failed to modify %s.%s: %s."),
				                 strv[0], strv[1], error->message);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
		} else {
			/* Remove value
			 * - either empty: remove whole value
			 * - or specified by index <0-n>: remove item at the index
			 * - or option name: remove item with the option name
			 */
			if (value) {
				unsigned long idx;
				if (nmc_string_to_uint (value, TRUE, 0, G_MAXUINT32, &idx))
					nmc_setting_remove_property_option (setting, property_name, NULL, idx, &error);
				else
					nmc_setting_remove_property_option (setting, property_name, value, 0, &error);
				if (error) {
					g_string_printf (nmc->return_text, _("Error: failed to remove a value from %s.%s: %s."),
					                 strv[0], strv[1], error->message);
					nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
					goto finish;
				}
			} else
				nmc_setting_reset_property (setting, property_name, NULL);
		}

		g_strfreev (strv);
		strv = NULL;
	}

	update_connection (!temporary, rc, modify_connection_cb, nmc);

finish:
	nmc->should_wait = (nmc->return_value == NMC_RESULT_SUCCESS);
	g_free (property_name);
	if (strv)
		g_strfreev (strv);
	g_clear_error (&error);
	return nmc->return_value;
}

static void
delete_cb (GObject *con, GAsyncResult *result, gpointer user_data)
{
	ConnectionCbInfo *info = (ConnectionCbInfo *) user_data;
	GError *error = NULL;

	if (!nm_remote_connection_delete_finish (NM_REMOTE_CONNECTION (con), result, &error)) {
		g_string_printf (info->nmc->return_text, _("Error: not all connections deleted."));
		g_printerr (_("Error: Connection deletion failed: %s"),
		            error->message);
		g_error_free (error);
		info->nmc->return_value = NMC_RESULT_ERROR_CON_DEL;
		connection_cb_info_finish (info, con);
	} else {
		if (info->nmc->nowait_flag)
			connection_cb_info_finish (info, con);
	}
}

static NMCResultCode
do_connection_delete (NmCli *nmc, int argc, char **argv)
{
	NMConnection *connection;
	ConnectionCbInfo *info = NULL;
	GSList *queue = NULL, *iter;
	char **arg_arr = NULL;
	char **arg_ptr = argv;
	int arg_num = argc;
	GString *invalid_cons = NULL;
	int pos = 0;

	if (nmc->timeout == -1)
		nmc->timeout = 10;

	if (argc == 0) {
		if (nmc->ask) {
			char *line = nmc_readline (PROMPT_CONNECTIONS);
			nmc_string_to_arg_array (line, NULL, TRUE, &arg_arr, &arg_num);
			g_free (line);
			arg_ptr = arg_arr;
		}
		if (arg_num == 0) {
			g_string_printf (nmc->return_text, _("Error: No connection specified."));
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto finish;
		}
	}

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

		connection = nmc_find_connection (nmc->connections, selector, *arg_ptr, &pos);
		if (connection) {
			/* Check if the connection is unique. */
			/* Calling delete for the same connection repeatedly would result in
			 * NM responding for the last D-Bus call only and we would stall. */
			if (!g_slist_find (queue, connection))
				queue = g_slist_prepend (queue, g_object_ref (connection));
		} else {
			g_printerr (_("Error: unknown connection '%s'\n"), *arg_ptr);
			g_string_printf (nmc->return_text, _("Error: not all active connections found."));
			nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
			if (!invalid_cons)
				invalid_cons = g_string_new (NULL);
			g_string_append_printf (invalid_cons, "'%s', ", *arg_ptr);
		}

		/* Take next argument (if there's no other connection of the same name) */
		if (!pos)
			next_arg (&arg_num, &arg_ptr);
	}

	if (!queue) {
		g_string_printf (nmc->return_text, _("Error: no connection provided."));
		nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
		goto finish;
	}
	queue = g_slist_reverse (queue);

	info = g_slice_new0 (ConnectionCbInfo);
	info->nmc = nmc;
	info->queue = queue;
	info->timeout_id = g_timeout_add_seconds (nmc->timeout, connection_op_timeout_cb, info);

	nmc->nowait_flag = (nmc->timeout == 0);
	nmc->should_wait = TRUE;

	g_signal_connect (nmc->client, NM_CLIENT_CONNECTION_REMOVED,
	                  G_CALLBACK (connection_removed_cb), info);

	/* Now delete the connections */
	for (iter = queue; iter; iter = g_slist_next (iter))
		nm_remote_connection_delete_async (NM_REMOTE_CONNECTION (iter->data),
		                                   NULL, delete_cb, info);

finish:
	if (invalid_cons) {
		g_string_truncate (invalid_cons, invalid_cons->len-2);  /* truncate trailing ", " */
		g_string_printf (nmc->return_text, _("Error: cannot delete unknown connection(s): %s."),
		                 invalid_cons->str);
		nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
		g_string_free (invalid_cons, TRUE);
	}
	g_strfreev (arg_arr);
	return nmc->return_value;
}

static NMCResultCode
do_connection_reload (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;

	nmc->return_value = NMC_RESULT_SUCCESS;
	nmc->should_wait = FALSE;

	if (!nm_client_get_nm_running (nmc->client)) {
		g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
		nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		return nmc->return_value;
	}

	if (!nm_client_reload_connections (nmc->client, NULL, &error)) {
		g_string_printf (nmc->return_text, _("Error: failed to reload connections: %s."),
		                 error->message);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		g_clear_error (&error);
	}

	return nmc->return_value;
}

static NMCResultCode
do_connection_load (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;
	char **filenames, **failures = NULL;
	int i;

	nmc->return_value = NMC_RESULT_SUCCESS;
	nmc->should_wait = FALSE;

	if (!nm_client_get_nm_running (nmc->client)) {
		g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
		nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		return nmc->return_value;
	}

	if (argc == 0) {
		g_string_printf (nmc->return_text, _("Error: No connection specified."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return nmc->return_value;
	}

	filenames = g_new (char *, argc + 1);
	for (i = 0; i < argc; i++)
		filenames[i] = argv[i];
	filenames[i] = NULL;

	nm_client_load_connections (nmc->client, filenames, &failures, NULL, &error);
	g_free (filenames);
	if (error) {
		g_string_printf (nmc->return_text, _("Error: failed to load connection: %s."),
		                 error->message);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		g_error_free (error);
	}

	if (failures) {
		for (i = 0; failures[i]; i++)
			g_printerr (_("Could not load file '%s'\n"), failures[i]);
		g_strfreev (failures);
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

static char *
gen_func_connection_names (const char *text, int state)
{
	int i;
	const char **connections;
	char *ret;

	if (nm_cli.connections->len == 0)
		return NULL;

	connections = g_new (const char *, nm_cli.connections->len + 1);
	for (i = 0; i < nm_cli.connections->len; i++) {
		NMConnection *con = NM_CONNECTION (nm_cli.connections->pdata[i]);
		const char *id = nm_connection_get_id (con);
		connections[i] = id;
	}
	connections[i] = NULL;

	ret = nmc_rl_gen_func_basic (text, state, connections);

	g_free (connections);
	return ret;
}

static char *
gen_func_active_connection_names (const char *text, int state)
{
	int i;
	const GPtrArray *acs;
	const char **connections;
	char *ret;

	if (!nm_cli.client)
		return NULL;

	acs = nm_client_get_active_connections (nm_cli.client);
	if (!acs || acs->len == 0)
		return NULL;

	connections = g_new (const char *, acs->len + 1);
	for (i = 0; i < acs->len; i++)
		connections[i] = nm_active_connection_get_id (acs->pdata[i]);
	connections[i] = NULL;

	ret = nmc_rl_gen_func_basic (text, state, connections);

	g_free (connections);
	return ret;
}

static char **
nmcli_con_tab_completion (const char *text, int start, int end)
{
	char **match_array = NULL;
	rl_compentry_func_t *generator_func = NULL;

	/* Disable readline's default filename completion */
	rl_attempted_completion_over = 1;

	if (g_strcmp0 (rl_prompt, PROMPT_CONNECTION) == 0) {
		/* Disable appending space after completion */
		rl_completion_append_character = '\0';

		if (!is_single_word (rl_line_buffer))
			return NULL;

		generator_func = gen_func_connection_names;
	} else if (g_strcmp0 (rl_prompt, PROMPT_CONNECTIONS) == 0) {
		generator_func = gen_func_connection_names;
	} else if (g_strcmp0 (rl_prompt, PROMPT_ACTIVE_CONNECTIONS) == 0) {
		generator_func = gen_func_active_connection_names;
	}

	if (generator_func)
		match_array = rl_completion_matches (text, generator_func);

	return match_array;
}

static GArray *
parse_preferred_connection_order (const char *order, GError **error)
{
	char **strv, **iter;
	const char *str;
	GArray *order_arr;
	NmcSortOrder val;
	gboolean inverse, unique;
	int i;

	strv = nmc_strsplit_set (order, ":", -1);
	if (!strv || !*strv) {
		g_set_error (error, NMCLI_ERROR, 0,
		             _("incorrect string '%s' of '--order' option"), order);
		g_strfreev (strv);
		return NULL;
	}

	order_arr = g_array_sized_new (FALSE, FALSE, sizeof (NmcSortOrder), 4);
	for (iter = strv; iter && *iter; iter++) {
		str = *iter;
		inverse = FALSE;
		if (str[0] == '-')
			inverse = TRUE;
		if (str[0] == '+' || str[0] == '-')
			str++;

		if (matches (str, "active") == 0)
			val = inverse ? NMC_SORT_ACTIVE_INV : NMC_SORT_ACTIVE;
		else if (matches (str, "name") == 0)
			val = inverse ? NMC_SORT_NAME_INV : NMC_SORT_NAME;
		else if (matches (str, "type") == 0)
			val = inverse ? NMC_SORT_TYPE_INV : NMC_SORT_TYPE;
		else if (matches (str, "path") == 0)
			val = inverse ? NMC_SORT_PATH_INV : NMC_SORT_PATH;
		else {
			g_array_unref (order_arr);
			order_arr = NULL;
			g_set_error (error, NMCLI_ERROR, 0,
			             _("incorrect item '%s' in '--order' option"), *iter);
			break;
		}
		/* Check for duplicates and ignore them. */
		unique = TRUE;
		for (i = 0; i < order_arr->len; i++) {
			if (abs (g_array_index (order_arr, NmcSortOrder, i)) - abs (val) == 0) {
				unique = FALSE;
				break;
			}
		}

		/* Value is ok and unique, add it to the array */
		if (unique)
			g_array_append_val (order_arr, val);
	}

	g_strfreev (strv);
	return order_arr;
}

/* Entry point function for connections-related commands: 'nmcli connection' */
NMCResultCode
do_connections (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;

	/* Register polkit agent */
	nmc_start_polkit_agent_start_try (nmc);

	/* Set completion function for 'nmcli con' */
	rl_attempted_completion_function = (rl_completion_func_t *) nmcli_con_tab_completion;

	/* Exit early on help */
	if (nmc_arg_is_help (*argv)) {
		usage ();
		return nmc->return_value;
	}
	if (argc != 0 && nmc_arg_is_help (*(argv+1))) {
		if (usage_connection_second_level (*argv))
			return nmc->return_value;
	}

	/* Get NMClient object early */
	nmc->get_client (nmc);

	/* Check whether NetworkManager is running */
	if (!nm_client_get_nm_running (nmc->client)) {
		g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
		nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		return nmc->return_value;
	}
	/* Compare NM and nmcli versions */
	if (!nmc_versions_match (nmc))
		return nmc->return_value;

	/* Get the connection list */
	nmc->connections = nm_client_get_connections (nmc->client);

	/* Now parse the command line and perform the required operation */
	if (argc == 0) {
		if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
			goto opt_error;
		nmc->return_value = do_connections_show (nmc, FALSE, FALSE, NULL, argc, argv);
	} else {
		if (matches (*argv, "show") == 0) {
			gboolean active = FALSE;
			gboolean show_secrets = FALSE;
			GArray *order = NULL;
			int i;

			next_arg (&argc, &argv);
			/* check connection show options [--active] [--show-secrets] */
			for (i = 0; i < 3; i++) {
				if (!active && nmc_arg_is_option (*argv, "active")) {
					active = TRUE;
					next_arg (&argc, &argv);
				}
				if (!show_secrets && nmc_arg_is_option (*argv, "show-secrets")) {
					show_secrets = TRUE;
					next_arg (&argc, &argv);
				}
				if (!order && nmc_arg_is_option (*argv, "order")) {
					if (next_arg (&argc, &argv) != 0) {
						g_set_error_literal (&error, NMCLI_ERROR, 0,
						                     _("'--order' argument is missing"));
						goto opt_error;
					}
					order = parse_preferred_connection_order (*argv, &error);
					if (error)
						goto opt_error;
					next_arg (&argc, &argv);
				}
			}
			nmc->return_value = do_connections_show (nmc, active, show_secrets, order, argc, argv);
			if (order)
				g_array_unref (order);
		} else if (matches(*argv, "up") == 0) {
			nmc->return_value = do_connection_up (nmc, argc-1, argv+1);
		} else if (matches(*argv, "down") == 0) {
			nmc->return_value = do_connection_down (nmc, argc-1, argv+1);
		} else if (matches(*argv, "add") == 0) {
			nmc->return_value = do_connection_add (nmc, argc-1, argv+1);
		} else if (matches(*argv, "edit") == 0) {
			nmc->should_wait = TRUE;
			editor_thread_data.nmc = nmc;
			editor_thread_data.argc = argc - 1;
			editor_thread_data.argv = argv + 1;
			editor_thread = g_thread_new ("editor-thread", connection_editor_thread_func, &editor_thread_data);
			g_thread_unref (editor_thread);
		} else if (matches(*argv, "delete") == 0) {
			nmc->return_value = do_connection_delete (nmc, argc-1, argv+1);
		} else if (matches(*argv, "reload") == 0) {
			nmc->return_value = do_connection_reload (nmc, argc-1, argv+1);
		} else if (matches(*argv, "load") == 0) {
			nmc->return_value = do_connection_load (nmc, argc-1, argv+1);
		} else if (matches (*argv, "modify") == 0) {
			gboolean temporary = FALSE;

			next_arg (&argc, &argv);
			if (nmc_arg_is_option (*argv, "temporary")) {
				temporary = TRUE;
				next_arg (&argc, &argv);
			}
			nmc->return_value = do_connection_modify (nmc, temporary, argc, argv);
		} else {
			usage ();
			g_string_printf (nmc->return_text, _("Error: '%s' is not valid 'connection' command."), *argv);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		}
	}

	return nmc->return_value;

opt_error:
	g_string_printf (nmc->return_text, _("Error: %s."), error->message);
	nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
	g_error_free (error);
	return nmc->return_value;
}
