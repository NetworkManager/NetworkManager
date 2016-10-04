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
#include "devices.h"
#include "nm-secret-agent-simple.h"
#include "polkit-agent.h"
#include "nm-vpn-helpers.h"

typedef struct _OptionInfo OptionInfo;
struct _OptionInfo {
	const char *setting_name;
	const char *property;
	const char *option;
	enum {
		OPTION_NONE = 0x00,
		OPTION_REQD = 0x01,	/* Don't ask to ask. */
		OPTION_DONT_ASK = 0x02,	/* Don't ask interactively by default */
		OPTION_MULTI = 0x04,	/* Ask multiple times, do an append instead of set. */

		OPTION_DISABLED = 0x10,	/* Don't ask due to runtime decision. */
		OPTION_ENABLED = 0x20,	/* Override OPTION_DONT_ASK due to runtime decision. */
	} flags;
	const char *prompt;
	const char *def_hint;
	gboolean (*check_and_set)(NmCli *nmc, NMConnection *connection, OptionInfo *option, const char *value, GError **error);
	rl_compentry_func_t *generator_func;
};

/* define some prompts for connection editor */
#define EDITOR_PROMPT_SETTING  _("Setting name? ")
#define EDITOR_PROMPT_PROPERTY _("Property name? ")
#define EDITOR_PROMPT_CON_TYPE _("Enter connection type: ")

/* define some other prompts */
#define PROMPT_CON_TYPE    N_("Connection type")
#define PROMPT_IFNAME      N_("Interface name [*]")
#define PROMPT_VPN_TYPE    N_("VPN type")
#define PROMPT_MASTER      N_("Master")

#define PROMPT_IB_MODE     N_("Transport mode")
#define WORD_DATAGRAM  "datagram"
#define WORD_CONNECTED "connected"
#define PROMPT_IB_MODE_CHOICES "(" WORD_DATAGRAM "/" WORD_CONNECTED ") [" WORD_DATAGRAM "]"

#define PROMPT_BT_TYPE N_("Bluetooth type")
#define WORD_PANU      "panu"
#define WORD_DUN_GSM   "dun-gsm"
#define WORD_DUN_CDMA  "dun-cdma"
#define PROMPT_BT_TYPE_CHOICES "(" WORD_PANU "/" WORD_DUN_GSM "/" WORD_DUN_CDMA ") [" WORD_PANU "]"

#define PROMPT_BOND_MODE N_("Bonding mode")

#define PROMPT_BOND_MON_MODE N_("Bonding monitoring mode")
#define WORD_MIIMON "miimon"
#define WORD_ARP    "arp"
#define PROMPT_BOND_MON_MODE_CHOICES "(" WORD_MIIMON "/" WORD_ARP ") [" WORD_MIIMON "]"

#define PROMPT_ADSL_PROTO N_("Protocol")
#define PROMPT_ADSL_PROTO_CHOICES "(" NM_SETTING_ADSL_PROTOCOL_PPPOA "/" NM_SETTING_ADSL_PROTOCOL_PPPOE "/" NM_SETTING_ADSL_PROTOCOL_IPOATM ")"

#define PROMPT_WIFI_MODE N_("Wi-Fi mode")
#define WORD_INFRA  "infrastructure"
#define WORD_AP     "ap"
#define WORD_ADHOC  "adhoc"
#define PROMPT_WIFI_MODE_CHOICES "(" WORD_INFRA "/" WORD_AP "/" WORD_ADHOC ") [" WORD_INFRA "]"

#define PROMPT_ADSL_ENCAP N_("ADSL encapsulation")
#define PROMPT_ADSL_ENCAP_CHOICES "(" NM_SETTING_ADSL_ENCAPSULATION_VCMUX "/" NM_SETTING_ADSL_ENCAPSULATION_LLC ") [none]"

#define PROMPT_TUN_MODE N_("Tun mode")
#define WORD_TUN  "tun"
#define WORD_TAP  "tap"
#define PROMPT_TUN_MODE_CHOICES "(" WORD_TUN "/" WORD_TAP ") [" WORD_TUN "]"

#define PROMPT_IP_TUNNEL_MODE N_("IP Tunnel mode")

#define PROMPT_MACVLAN_MODE N_("MACVLAN mode")

#define PROMPT_CONNECTION  _("Connection (name, UUID, or path)")
#define PROMPT_VPN_CONNECTION  _("VPN connection (name, UUID, or path)")
#define PROMPT_CONNECTIONS _("Connection(s) (name, UUID, or path)")
#define PROMPT_ACTIVE_CONNECTIONS _("Connection(s) (name, UUID, path or apath)")

#define BASE_PROMPT "nmcli> "

/* Available fields for 'connection show' */
NmcOutputField nmc_fields_con_show[] = {
	{"NAME",                 N_("NAME")},                  /* 0 */
	{"UUID",                 N_("UUID")},                  /* 1 */
	{"TYPE",                 N_("TYPE")},                  /* 2 */
	{"TIMESTAMP",            N_("TIMESTAMP")},             /* 3 */
	{"TIMESTAMP-REAL",       N_("TIMESTAMP-REAL")},        /* 4 */
	{"AUTOCONNECT",          N_("AUTOCONNECT")},           /* 5 */
	{"AUTOCONNECT-PRIORITY", N_("AUTOCONNECT-PRIORITY")},  /* 6 */
	{"READONLY",             N_("READONLY")},              /* 7 */
	{"DBUS-PATH",            N_("DBUS-PATH")},             /* 8 */
	{"ACTIVE",               N_("ACTIVE")},                /* 9 */
	{"DEVICE",               N_("DEVICE")},                /* 10 */
	{"STATE",                N_("STATE")},                 /* 11 */
	{"ACTIVE-PATH",          N_("ACTIVE-PATH")},           /* 12 */
	{NULL, NULL}
};
#define NMC_FIELDS_CON_SHOW_ALL     "NAME,UUID,TYPE,TIMESTAMP,TIMESTAMP-REAL,AUTOCONNECT,AUTOCONNECT-PRIORITY,READONLY,DBUS-PATH,"\
                                    "ACTIVE,DEVICE,STATE,ACTIVE-PATH"
#define NMC_FIELDS_CON_SHOW_COMMON  "NAME,UUID,TYPE,DEVICE"

/* Helper macro to define fields */
#define SETTING_FIELD(setting, props) { setting, N_(setting), 0, props, NULL, FALSE, FALSE, 0 }

/* Available settings for 'connection show <con>' - profile part */
NmcOutputField nmc_fields_settings_names[] = {
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
	SETTING_FIELD (NM_SETTING_TUN_SETTING_NAME,               nmc_fields_setting_tun + 1),               /* 25 */
	SETTING_FIELD (NM_SETTING_IP_TUNNEL_SETTING_NAME,         nmc_fields_setting_ip_tunnel + 1),         /* 26 */
	SETTING_FIELD (NM_SETTING_MACVLAN_SETTING_NAME,           nmc_fields_setting_macvlan + 1),           /* 27 */
	SETTING_FIELD (NM_SETTING_VXLAN_SETTING_NAME,             nmc_fields_setting_vxlan + 1),             /* 28 */
	SETTING_FIELD (NM_SETTING_PROXY_SETTING_NAME,             nmc_fields_setting_proxy + 1),             /* 29 */
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
                                         NM_SETTING_DCB_SETTING_NAME"," \
                                         NM_SETTING_TUN_SETTING_NAME"," \
                                         NM_SETTING_IP_TUNNEL_SETTING_NAME"," \
                                         NM_SETTING_MACVLAN_SETTING_NAME"," \
                                         NM_SETTING_VXLAN_SETTING_NAME"," \
                                         NM_SETTING_PROXY_SETTING_NAME
#define NMC_FIELDS_SETTINGS_NAMES_ALL    NMC_FIELDS_SETTINGS_NAMES_ALL_X

/* Active connection data */
/* Available fields for GENERAL group */
NmcOutputField nmc_fields_con_active_details_general[] = {
	{"GROUP",         N_("GROUP")},        /* 0 */
	{"NAME",          N_("NAME")},         /* 1 */
	{"UUID",          N_("UUID")},         /* 2 */
	{"DEVICES",       N_("DEVICES")},      /* 3 */
	{"STATE",         N_("STATE")},        /* 4 */
	{"DEFAULT",       N_("DEFAULT")},      /* 5 */
	{"DEFAULT6",      N_("DEFAULT6")},     /* 6 */
	{"SPEC-OBJECT",   N_("SPEC-OBJECT")},  /* 7 */
	{"VPN",           N_("VPN")},          /* 8 */
	{"DBUS-PATH",     N_("DBUS-PATH")},    /* 9 */
	{"CON-PATH",      N_("CON-PATH")},     /* 10 */
	{"ZONE",          N_("ZONE")},         /* 11 */
	{"MASTER-PATH",   N_("MASTER-PATH")},  /* 12 */
	{NULL, NULL}
};
#define NMC_FIELDS_CON_ACTIVE_DETAILS_GENERAL_ALL  "GROUP,NAME,UUID,DEVICES,STATE,DEFAULT,DEFAULT6,"\
                                                   "VPN,ZONE,DBUS-PATH,CON-PATH,SPEC-OBJECT,MASTER-PATH"

/* IP group is handled by common.c */

/* Available fields for VPN group */
NmcOutputField nmc_fields_con_active_details_vpn[] = {
	{"GROUP",     N_("GROUP")},      /* 0 */
	{"TYPE",      N_("TYPE")},       /* 1 */
	{"USERNAME",  N_("USERNAME")},   /* 2 */
	{"GATEWAY",   N_("GATEWAY")},    /* 3 */
	{"BANNER",    N_("BANNER")},     /* 4 */
	{"VPN-STATE", N_("VPN-STATE")},  /* 5 */
	{"CFG",       N_("CFG")},        /* 6 */
	{NULL, NULL}
};
#define NMC_FIELDS_CON_ACTIVE_DETAILS_VPN_ALL  "GROUP,TYPE,USERNAME,GATEWAY,BANNER,VPN-STATE,CFG"

/* defined in common.c */
extern NmcOutputField nmc_fields_ip4_config[];
extern NmcOutputField nmc_fields_ip6_config[];
extern NmcOutputField nmc_fields_dhcp4_config[];
extern NmcOutputField nmc_fields_dhcp6_config[];

/* Available fields for 'connection show <con>' - active part */
NmcOutputField nmc_fields_con_active_details_groups[] = {
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

static char *gen_connection_types (const char *text, int state);

static void
usage (void)
{
	g_printerr (_("Usage: nmcli connection { COMMAND | help }\n\n"
	              "COMMAND := { show | up | down | add | modify | clone | edit | delete | monitor | reload | load | import | export }\n\n"
	              "  show [--active] [--order <order spec>]\n"
	              "  show [--active] [id | uuid | path | apath] <ID> ...\n\n"
	              "  up [[id | uuid | path] <ID>] [ifname <ifname>] [ap <BSSID>] [passwd-file <file with passwords>]\n\n"
	              "  down [id | uuid | path | apath] <ID> ...\n\n"
	              "  add COMMON_OPTIONS TYPE_SPECIFIC_OPTIONS SLAVE_OPTIONS IP_OPTIONS [-- ([+|-]<setting>.<property> <value>)+]\n\n"
	              "  modify [--temporary] [id | uuid | path] <ID> ([+|-]<setting>.<property> <value>)+\n\n"
	              "  clone [--temporary] [id | uuid | path ] <ID> <new name>\n\n"
	              "  edit [id | uuid | path] <ID>\n"
	              "  edit [type <new_con_type>] [con-name <new_con_name>]\n\n"
	              "  delete [id | uuid | path] <ID>\n\n"
	              "  monitor [id | uuid | path] <ID> ...\n\n"
	              "  reload\n\n"
	              "  load <filename> [ <filename>... ]\n\n"
	              "  import [--temporary] type <type> file <file to import>\n\n"
	              "  export [id | uuid | path] <ID> [<output file>]\n\n"));
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
	              "ARGUMENTS := [--active] [id | uuid | path | apath] <ID> ...\n"
	              "\n"
	              "Show details for specified connections. By default, both static configuration\n"
	              "and active connection data are displayed. It is possible to filter the output\n"
	              "using global '--fields' option. Refer to the manual page for more information.\n"
	              "When --active option is specified, only the active profiles are taken into\n"
	              "account. Use global --show-secrets option to reveal associated secrets as well.\n"));
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
	              "ARGUMENTS := COMMON_OPTIONS TYPE_SPECIFIC_OPTIONS SLAVE_OPTIONS IP_OPTIONS [-- ([+|-]<setting>.<property> <value>)+]\n\n"
	              "  COMMON_OPTIONS:\n"
	              "                  type <type>\n"
	              "                  ifname <interface name> | \"*\"\n"
	              "                  [con-name <connection name>]\n"
	              "                  [autoconnect yes|no]\n"
	              "                  [save yes|no]\n"
	              "                  [master <master (ifname, or connection UUID or name)>]\n"
	              "                  [slave-type <master connection type>]\n\n"
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
	              "    vlan:         dev <parent device (connection UUID, ifname, or MAC)>\n"
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
	              "    adsl:         username <username>\n"
	              "                  protocol pppoa|pppoe|ipoatm\n"
	              "                  [password <password>]\n"
	              "                  [encapsulation vcmux|llc]\n\n"
	              "    tun:          mode tun|tap\n"
	              "                  [owner <UID>]\n"
	              "                  [group <GID>]\n"
	              "                  [pi yes|no]\n"
	              "                  [vnet-hdr yes|no]\n"
	              "                  [multi-queue yes|no]\n\n"
	              "    ip-tunnel:    mode ipip|gre|sit|isatap|vti|ip6ip6|ipip6|ip6gre|vti6\n"
	              "                  remote <remote endpoint IP>\n"
	              "                  [local <local endpoint IP>]\n"
	              "                  [dev <parent device (ifname or connection UUID)>]\n\n"
	              "    macvlan:      dev <parent device (connection UUID, ifname, or MAC)>\n"
	              "                  mode vepa|bridge|private|passthru|source\n"
	              "                  [tap yes|no]\n\n"
	              "    vxlan:        id <VXLAN ID>\n"
	              "                  remote <IP of multicast group or remote address>\n"
	              "                  [local <source IP>]\n"
	              "                  [dev <parent device (ifname or connection UUID)>]\n"
	              "                  [source-port-min <0-65535>]\n"
	              "                  [source-port-max <0-65535>]\n"
	              "                  [destination-port <0-65535>]\n\n"
	              "  SLAVE_OPTIONS:\n"
	              "    bridge:       [priority <0-63>]\n"
	              "                  [path-cost <1-65535>]\n"
	              "                  [hairpin yes|no]\n\n"
	              "    team:         [config <file>|<raw JSON data>]\n\n"
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
usage_connection_clone (void)
{
	g_printerr (_("Usage: nmcli connection clone { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [--temporary] [id | uuid | path] <ID> <new name>\n"
	              "\n"
	              "Clone an existing connection profile. The newly created connection will be\n"
	              "the exact copy of the <ID>, except the uuid property (will be generated) and\n"
	              "id (provided as <new name> argument).\n\n"));
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
usage_connection_monitor (void)
{
	g_printerr (_("Usage: nmcli connection monitor { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [id | uuid | path] <ID> ...\n"
	              "\n"
	              "Monitor connection profile activity.\n"
	              "This command prints a line whenever the specified connection changes.\n"
	              "Monitors all connection profiles in case none is specified.\n\n"));
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

static void
usage_connection_import (void)
{
	g_printerr (_("Usage: nmcli connection import { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [--temporary] type <type> file <file to import>\n"
	              "\n"
	              "Import an external/foreign configuration as a NetworkManager connection profile.\n"
	              "The type of the input file is specified by type option.\n"
	              "Only VPN configurations are supported at the moment. The configuration\n"
	              "is imported by NetworkManager VPN plugins.\n\n"));
}

static void
usage_connection_export (void)
{
	g_printerr (_("Usage: nmcli connection export { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [id | uuid | path] <ID> [<output file>]\n"
	              "\n"
	              "Export a connection. Only VPN connections are supported at the moment.\n"
	              "The data are directed to standard output or to a file if a name is given.\n\n"));
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
                        int *idx,
                        gboolean complete)
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
		if (!filter_type || strcmp (filter_type, "id")  == 0) {
			if (complete)
				nmc_complete_strings (filter_val, id, NULL);
			if (strcmp (filter_val, id) == 0)
				goto found;
		}

		if (!filter_type || strcmp (filter_type, "uuid") == 0) {
			if (complete && (filter_type || *filter_val))
				nmc_complete_strings (filter_val, uuid, NULL);
			if (strcmp (filter_val, uuid) == 0)
				goto found;
		}

		if (!filter_type || strcmp (filter_type, "path") == 0) {
			if (complete && (filter_type || *filter_val))
				nmc_complete_strings (filter_val, path, filter_type ? path_num : NULL, NULL);
		        if (g_strcmp0 (filter_val, path) == 0 || (filter_type && g_strcmp0 (filter_val, path_num) == 0))
				goto found;
		}

		if (!filter_type || strcmp (filter_type, "apath") == 0) {
			if (complete && (filter_type || *filter_val))
				nmc_complete_strings (filter_val, a_path, filter_type ? a_path_num : NULL, NULL);
		        if (g_strcmp0 (filter_val, a_path) == 0 || (filter_type && g_strcmp0 (filter_val, a_path_num) == 0))
				goto found;
		}

		continue;
found:
		if (!idx)
			return candidate;
		if (found) {
			*idx = i;
			return found;
		}
		found = candidate;
	}

	if (idx)
		*idx = 0;
	return found;
}

void
nmc_active_connection_state_to_color (NMActiveConnectionState state, NmcTermColor *color)
{
	*color = NMC_TERM_COLOR_NORMAL;

	if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATING)
		*color = NMC_TERM_COLOR_YELLOW;
	else if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED)
		*color = NMC_TERM_COLOR_GREEN;
	else if (state > NM_ACTIVE_CONNECTION_STATE_ACTIVATED)
		*color = NMC_TERM_COLOR_RED;
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
	NmcTermColor color;

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
	nmc_active_connection_state_to_color (ac_state_int, &color);
	set_val_color_all (arr, color);

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

	if (!cons)
		return NULL;

	compare_info.nmc = nmc;
	compare_info.order = order;

	sorted = g_ptr_array_sized_new (cons->len);
	for (i = 0; i < cons->len; i++)
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

static NMConnection *
get_connection (NmCli *nmc, int *argc, char ***argv, int *pos, GError **error)
{
	NMConnection *connection = NULL;
	const char *selector = NULL;

	if (*argc == 0) {
		g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		                     _("No connection specified"));
		return NULL;
	}

	if (*argc == 1 && nmc->complete)
		nmc_complete_strings (**argv, "id", "uuid", "path", NULL);

	if (   strcmp (**argv, "id") == 0
	    || strcmp (**argv, "uuid") == 0
	    || strcmp (**argv, "path") == 0) {
		selector = **argv;
		if (next_arg (argc, argv) != 0) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("%s argument is missing"), selector);
			return NULL;
		}
	}

	connection = nmc_find_connection (nmc->connections, selector, **argv, pos,
	                                  *argc == 1 && nmc->complete);
	if (!connection) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_NOT_FOUND,
		             _("unknown connection '%s'"), **argv);
	}

	/* If the caller wants multiple results (pos is set) and there are any,
	 * don't switch to next argument.
	 */
	if (!pos || !*pos)
		next_arg (argc, argv);

	return connection;
}

static NMCResultCode
do_connections_show (NmCli *nmc, int argc, char **argv)
{
	GError *err = NULL;
	char *profile_flds = NULL, *active_flds = NULL;
	GPtrArray *invisibles, *sorted_cons;
	gboolean active_only = FALSE;
	gboolean show_secrets = FALSE;
	GArray *order = NULL;
	int i;

	/* check connection show options [--active] [--show-secrets] */
	for (i = 0; i < 3; i++) {
		if (argc == 1 && nmc->complete) {
			nmc_complete_strings (*argv, "--active", "--show-secrets",
			                             "--order", NULL);
		}

		if (!active_only && nmc_arg_is_option (*argv, "active")) {
			active_only = TRUE;
			next_arg (&argc, &argv);
		} else if (!show_secrets && nmc_arg_is_option (*argv, "show-secrets")) {
			/* --show-secrets is deprecated in favour of global --show-secrets */
			/* Keep it here for backwards compatibility */
			show_secrets = TRUE;
			next_arg (&argc, &argv);
		} else if (!order && nmc_arg_is_option (*argv, "order")) {
			if (next_arg (&argc, &argv) != 0) {
				g_set_error_literal (&err, NMCLI_ERROR, 0,
				                     _("'--order' argument is missing"));
				goto finish;
			}
			/* TODO: complete --order */
			order = parse_preferred_connection_order (*argv, &err);
			if (err)
				goto finish;
			next_arg (&argc, &argv);
		} else {
			break;
		}
	}
	show_secrets = nmc->show_secrets || show_secrets;

	if (argc == 0) {
		char *fields_str;
		char *fields_all =    NMC_FIELDS_CON_SHOW_ALL;
		char *fields_common = NMC_FIELDS_CON_SHOW_COMMON;
		NmcOutputField *tmpl, *arr;
		size_t tmpl_len;

		if (nmc->complete)
			goto finish;

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
		g_ptr_array_free (invisibles, TRUE);

		/* Sort the connections and fill the output data */
		sorted_cons = sort_connections (nmc->connections, nmc, order);
		for (i = 0; i < sorted_cons->len; i++)
			fill_output_connection (sorted_cons->pdata[i], nmc, active_only);
		g_ptr_array_free (sorted_cons, TRUE);

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

			if (argc == 1 && nmc->complete)
				nmc_complete_strings (*argv, "id", "uuid", "path", "apath", NULL);

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

			/* Try to find connection by id, uuid or path first */
			con = nmc_find_connection (nmc->connections, selector, *argv, &pos,
			                           argc == 1 && nmc->complete);
			if (!con && (!selector || strcmp (selector, "apath") == 0)) {
				/* Try apath too */
				acon = find_active_connection (active_cons, nmc->connections, "apath", *argv, NULL,
				                               argc == 1 && nmc->complete);
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

			if (nmc->complete) {
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
	if (order)
		g_array_unref (order);
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
				if (!nm_streq0 (dev_iface, iface))
					continue;

				if (!nm_device_connection_compatible (dev, connection, error)) {
					g_prefix_error (error, _("device '%s' not compatible with connection '%s':"),
					                iface, nm_setting_connection_get_id (s_con));
					return FALSE;
				}

			} else {
				if (!nm_device_connection_compatible (dev, connection, NULL))
					continue;
			}

			found_device = dev;
			if (ap && !strcmp (con_type, NM_SETTING_WIRELESS_SETTING_NAME) && NM_IS_DEVICE_WIFI (dev)) {
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

typedef struct {
	NmCli *nmc;
	NMDevice *device;
	NMActiveConnection *active;
} ActivateConnectionInfo;

static void activate_connection_info_finish (ActivateConnectionInfo *info);

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
device_state_cb (NMDevice *device, GParamSpec *pspec, ActivateConnectionInfo *info)
{
	NmCli *nmc = info->nmc;
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
		activate_connection_info_finish (info);
	} else if (   ac_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATING
	           && state >= NM_DEVICE_STATE_IP_CONFIG
	           && state <= NM_DEVICE_STATE_ACTIVATED) {
		if (nmc->print_output == NMC_PRINT_PRETTY)
			nmc_terminal_erase_line ();
		g_print (_("Connection successfully activated (master waiting for slaves) (D-Bus active path: %s)\n"),
		         nm_object_get_path (NM_OBJECT (active)));
		activate_connection_info_finish (info);
	}
}

static void
active_connection_removed_cb (NMClient *client, NMActiveConnection *active, ActivateConnectionInfo *info)
{
	NmCli *nmc = info->nmc;

	if (active == info->active) {
		g_string_printf (nmc->return_text, _("Error: Connection activation failed."));
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		activate_connection_info_finish (info);
	}
}

static void
active_connection_state_cb (NMActiveConnection *active, GParamSpec *pspec, ActivateConnectionInfo *info)
{
	NmCli *nmc = info->nmc;
	NMActiveConnectionState state;

	state = nm_active_connection_get_state (active);

	if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
		if (nmc->print_output == NMC_PRINT_PRETTY)
			nmc_terminal_erase_line ();
		g_print (_("Connection successfully activated (D-Bus active path: %s)\n"),
		         nm_object_get_path (NM_OBJECT (active)));
		activate_connection_info_finish (info);
	} else if (state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED) {
		g_string_printf (nmc->return_text, _("Error: Connection activation failed."));
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		activate_connection_info_finish (info);
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
			g_signal_connect (device, "notify::" NM_DEVICE_STATE, G_CALLBACK (device_state_cb), info);
			device_state_cb (device, NULL, info);
		}
	}
}

static void
vpn_connection_state_cb (NMVpnConnection *vpn,
                         NMVpnConnectionState state,
                         NMVpnConnectionStateReason reason,
                         ActivateConnectionInfo *info)
{
	NmCli *nmc = info->nmc;

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
		activate_connection_info_finish (info);
		break;

	case NM_VPN_CONNECTION_STATE_FAILED:
	case NM_VPN_CONNECTION_STATE_DISCONNECTED:
		g_string_printf (nmc->return_text, _("Error: Connection activation failed: %s."),
		                 vpn_connection_state_reason_to_string (reason));
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		activate_connection_info_finish (info);
		break;

	default:
		break;
	}
}

static void
set_nmc_error_timeout (NmCli *nmc)
{
	g_string_printf (nmc->return_text, _("Error: Timeout expired (%d seconds)"), nmc->timeout);
	nmc->return_value = NMC_RESULT_ERROR_TIMEOUT_EXPIRED;
}

static gboolean
activate_connection_timeout_cb (gpointer user_data)
{
	ActivateConnectionInfo *info = user_data;

	/* Time expired -> exit nmcli */
	set_nmc_error_timeout (info->nmc);
	activate_connection_info_finish (info);
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

static void
activate_connection_info_finish (ActivateConnectionInfo *info)
{
	if (info->device) {
		g_signal_handlers_disconnect_by_func (info->device, G_CALLBACK (device_state_cb), info);
		g_object_unref (info->device);
	}

	if (info->active) {
		if (NM_IS_VPN_CONNECTION (info->active))
			g_signal_handlers_disconnect_by_func (info->active, G_CALLBACK (vpn_connection_state_cb), info);
		else
			g_signal_handlers_disconnect_by_func (info->active, G_CALLBACK (active_connection_state_cb), info);
		g_object_unref (info->active);

	}
	g_signal_handlers_disconnect_by_func (info->nmc->client, G_CALLBACK (active_connection_removed_cb), info);

	g_free (info);
	quit ();
}

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

	info->active = active = nm_client_activate_connection_finish (NM_CLIENT (client), result, &error);

	if (error) {
		g_string_printf (nmc->return_text, _("Error: Connection activation failed: %s"),
		                 error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		activate_connection_info_finish (info);
	} else {
		state = nm_active_connection_get_state (active);
		if (!device) {
			/* device could be NULL for virtual devices. Fill it here. */
			ac_devs = nm_active_connection_get_devices (active);
			device = ac_devs->len > 0 ? g_ptr_array_index (ac_devs, 0) : NULL;
			if (device)
				info->device = g_object_ref (device);
		}

		if (nmc->nowait_flag || state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
			/* User doesn't want to wait or already activated */
			if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
				if (nmc->print_output == NMC_PRINT_PRETTY)
					nmc_terminal_erase_line ();
				g_print (_("Connection successfully activated (D-Bus active path: %s)\n"),
				         nm_object_get_path (NM_OBJECT (active)));
			}
			activate_connection_info_finish (info);
		} else {
			if (NM_IS_VPN_CONNECTION (active)) {
				/* Monitor VPN state */
				g_signal_connect (G_OBJECT (active), "vpn-state-changed", G_CALLBACK (vpn_connection_state_cb), info);

				/* Start progress indication showing VPN states */
				if (nmc->print_output == NMC_PRINT_PRETTY) {
					if (progress_id)
						g_source_remove (progress_id);
					progress_id = g_timeout_add (120, progress_vpn_cb, NM_VPN_CONNECTION (active));
				}
			} else {
				g_signal_connect (active, "notify::state", G_CALLBACK (active_connection_state_cb), info);
				active_connection_state_cb (active, NULL, info);

				/* Start progress indication showing device states */
				if (nmc->print_output == NMC_PRINT_PRETTY) {
					if (progress_id)
						g_source_remove (progress_id);
					progress_id = g_timeout_add (120, progress_device_cb, device);
				}
			}

			/* Start timer not to loop forever when signals are not emitted */
			g_timeout_add_seconds (nmc->timeout, activate_connection_timeout_cb, info);

			/* Fail when the active connection goes away. */
			g_signal_connect (nmc->client, NM_CLIENT_ACTIVE_CONNECTION_REMOVED,
			                  G_CALLBACK (active_connection_removed_cb), info);
		}
	}
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
			             "%s", local->message);
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
		g_signal_connect (nmc->secret_agent,
		                  NM_SECRET_AGENT_SIMPLE_REQUEST_SECRETS,
		                  G_CALLBACK (nmc_secrets_requested),
		                  nmc);
		if (connection) {
			nm_secret_agent_simple_enable (NM_SECRET_AGENT_SIMPLE (nmc->secret_agent),
			                               nm_object_get_path (NM_OBJECT (connection)));
		}
	}

	info = g_malloc0 (sizeof (ActivateConnectionInfo));
	info->nmc = nmc;
	if (device)
		info->device = g_object_ref (device);

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
	gs_free_error GError *error = NULL;
	char **arg_arr = NULL;
	int arg_num;
	char ***argv_ptr = &argv;
	int *argc_ptr = &argc;

	/*
	 * Set default timeout for connection activation.
	 * Activation can take quite a long time, use 90 seconds.
	 */
	if (nmc->timeout == -1)
		nmc->timeout = 90;

	if (argc == 0 && nmc->ask) {
		char *line;

		/* nmc_do_cmd() should not call this with argc=0. */
		g_assert (!nmc->complete);

		line = nmc_readline ("%s: ", PROMPT_CONNECTION);
		nmc_string_to_arg_array (line, NULL, TRUE, &arg_arr, &arg_num);
		g_free (line);
		argv_ptr = &arg_arr;
		argc_ptr = &arg_num;
	}

	if (argc > 0 && strcmp (*argv, "ifname") != 0) {
		connection = get_connection (nmc, argc_ptr, argv_ptr, NULL, &error);
		if (!connection) {
			g_string_printf (nmc->return_text, _("Error: %s."), error->message);
			return error->code;
		}
	}

	while (argc > 0) {
		if (argc == 1 && nmc->complete)
			nmc_complete_strings (*argv, "ifname", "ap", "passwd-file", NULL);

		if (strcmp (*argv, "ifname") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				return NMC_RESULT_ERROR_USER_INPUT;
			}

			ifname = *argv;
			if (argc == 1 && nmc->complete)
				nmc_complete_device (nmc->client, ifname, ap != NULL);
		}
		else if (strcmp (*argv, "ap") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				return NMC_RESULT_ERROR_USER_INPUT;
			}

			ap = *argv;
			if (argc == 1 && nmc->complete)
				nmc_complete_bssid (nmc->client, ifname, ap);
		}
		else if (strcmp (*argv, "passwd-file") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				return NMC_RESULT_ERROR_USER_INPUT;
			}

			if (argc == 1 && nmc->complete)
				nmc->return_value = NMC_RESULT_COMPLETE_FILE;

			pwds = *argv;
		}
		else if (!nmc->complete) {
			g_printerr (_("Unknown parameter: %s\n"), *argv);
		}

		argc--;
		argv++;
	}

	if (nmc->complete)
		return nmc->return_value;

	/* Use nowait_flag instead of should_wait because exiting has to be postponed till
	 * active_connection_state_cb() is called. That gives NM time to check our permissions
	 * and we can follow activation progress.
	 */
	nmc->nowait_flag = (nmc->timeout == 0);
	nmc->should_wait++;

	if (!nmc_activate_connection (nmc, connection, ifname, ap, nsp, pwds, activate_connection_cb, &error)) {
		g_string_printf (nmc->return_text, _("Error: %s."),
		                 error->message);
		nmc->should_wait--;
		return error->code;
	}

	/* Start progress indication */
	if (nmc->print_output == NMC_PRINT_PRETTY)
		progress_id = g_timeout_add (120, progress_cb, _("preparing"));

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

	set_nmc_error_timeout (info->nmc);
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
		/* nmc_do_cmd() should not call this with argc=0. */
		g_assert (!nmc->complete);

		if (nmc->ask) {
			char *line = nmc_readline (PROMPT_ACTIVE_CONNECTIONS);
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

	/* Get active connections */
	active_cons = nm_client_get_active_connections (nmc->client);
	while (arg_num > 0) {
		const char *selector = NULL;

		if (arg_num == 1)
			nmc_complete_strings (*arg_ptr, "id", "uuid", "path", "apath", NULL);

		if (   strcmp (*arg_ptr, "id") == 0
		    || strcmp (*arg_ptr, "uuid") == 0
		    || strcmp (*arg_ptr, "path") == 0
		    || strcmp (*arg_ptr, "apath") == 0) {

			selector = *arg_ptr;
			if (next_arg (&arg_num, &arg_ptr) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), selector);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
		}

		active = find_active_connection (active_cons, nmc->connections, selector, *arg_ptr, &idx,
		                                 arg_num == 1 && nmc->complete);
		if (active) {
			/* Check if the connection is unique. */
			/* Calling down for the same connection repeatedly would result in
			 * NM responding for the last D-Bus call only and we would stall. */
			if (!g_slist_find (queue, active))
				queue = g_slist_prepend (queue, g_object_ref (active));
		} else {
			if (!nmc->complete)
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
		goto finish;
	} else if (nmc->complete) {
		g_slist_free (queue);
		goto finish;
	}
	queue = g_slist_reverse (queue);

	if (nmc->timeout > 0) {
		nmc->should_wait++;

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

finish:
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
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_ethernet_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet", NULL, TRUE  },
	{ NM_SETTING_802_1X_SETTING_NAME,     NULL,       NULL, FALSE },
	{ NM_SETTING_DCB_SETTING_NAME,        NULL,       NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_infiniband_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL, NULL, TRUE  },
	{ NM_SETTING_INFINIBAND_SETTING_NAME, NULL, NULL, TRUE  },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_wifi_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME,        NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRELESS_SETTING_NAME,          "wifi",     NULL, TRUE  },
	{ NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, "wifi-sec", NULL, FALSE },
	{ NM_SETTING_802_1X_SETTING_NAME,            NULL,       NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_wimax_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,   NULL, TRUE  },
	{ NM_SETTING_WIMAX_SETTING_NAME,      NULL,   NULL, TRUE  },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_gsm_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_GSM_SETTING_NAME,        NULL,       NULL, TRUE  },
	{ NM_SETTING_SERIAL_SETTING_NAME,     NULL,       NULL, FALSE },
	{ NM_SETTING_PPP_SETTING_NAME,        NULL,       NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_cdma_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_CDMA_SETTING_NAME,       NULL,       NULL, TRUE  },
	{ NM_SETTING_SERIAL_SETTING_NAME,     NULL,       NULL, FALSE },
	{ NM_SETTING_PPP_SETTING_NAME,        NULL,       NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_bluetooth_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,   NULL, TRUE  },
	{ NM_SETTING_BLUETOOTH_SETTING_NAME,  NULL,   NULL, TRUE  },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_adsl_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,   NULL, TRUE  },
	{ NM_SETTING_ADSL_SETTING_NAME,       NULL,   NULL, TRUE  },
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
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_olpc_mesh_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,        NULL, TRUE  },
	{ NM_SETTING_OLPC_MESH_SETTING_NAME,  "olpc-mesh", NULL, TRUE  },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_vpn_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,   NULL, TRUE  },
	{ NM_SETTING_VPN_SETTING_NAME,        NULL,   NULL, TRUE  },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_vlan_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet", NULL, FALSE },
	{ NM_SETTING_VLAN_SETTING_NAME,       NULL,       NULL, TRUE  },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_bond_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_BOND_SETTING_NAME,       NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet", NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_team_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_TEAM_SETTING_NAME,       NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet", NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_bridge_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_BRIDGE_SETTING_NAME,     NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet", NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_bond_slave_settings [] = {
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_team_slave_settings [] = {
	{ NM_SETTING_TEAM_PORT_SETTING_NAME,  NULL,       NULL, TRUE  },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_bridge_slave_settings [] = {
	{ NM_SETTING_BRIDGE_PORT_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_no_slave_settings [] = {
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME, NULL,   NULL, FALSE },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME, NULL,   NULL, FALSE },
	{ NM_SETTING_PROXY_SETTING_NAME,      NULL,   NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_tun_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_TUN_SETTING_NAME,        NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet", NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_ip_tunnel_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_IP_TUNNEL_SETTING_NAME,  NULL,       NULL, TRUE  },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_macvlan_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME, NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,      "ethernet", NULL, FALSE },
	{ NM_SETTING_MACVLAN_SETTING_NAME,    NULL,       NULL, TRUE  },
	{ NULL, NULL, NULL, FALSE }
};

static const NameItem nmc_vxlan_settings [] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME,  NULL,       NULL, TRUE  },
	{ NM_SETTING_VXLAN_SETTING_NAME,       NULL,       NULL, TRUE  },
	{ NM_SETTING_WIRED_SETTING_NAME,       "ethernet", NULL, FALSE },
	{ NULL, NULL, NULL, FALSE }
};

/* Available connection types */
static const NameItem nmc_valid_connection_types[] = {
	{ NM_SETTING_GENERIC_SETTING_NAME,    NULL,        nmc_generic_settings      }, /* Needs to be first. */
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
	{ "no-slave",                         NULL,        nmc_no_slave_settings     },
	{ NM_SETTING_TUN_SETTING_NAME,        NULL,        nmc_tun_settings          },
	{ NM_SETTING_IP_TUNNEL_SETTING_NAME,  NULL,        nmc_ip_tunnel_settings    },
	{ NM_SETTING_MACVLAN_SETTING_NAME,    NULL,        nmc_macvlan_settings      },
	{ NM_SETTING_VXLAN_SETTING_NAME,      NULL,        nmc_vxlan_settings        },
	{ NULL, NULL, NULL }
};

/*
 * Return the most approopriate name for the connection of a type 'name' possibly with given 'slave_type'
 * if exists, else return the 'name'. The returned string must not be freed.
 */
static const char *
get_name_alias (const char *name, const char *slave_type, const NameItem array[])
{
	const NameItem *iter = &array[0];

	if (slave_type) {
		while (iter && iter->name) {
			if (   g_str_has_prefix (iter->name, slave_type)
			    && g_str_has_suffix (iter->name, "-slave"))
				break;
			iter++;
		}
	} else if (name) {
		while (iter && iter->name) {
			if (!strcmp (name, iter->name))
				break;
			iter++;
		}
	} else
		return NULL;

	if (iter) {
		if (iter->alias)
			return iter->alias;
		else
			return iter->name;
	}

	return name;
}

/*
 * Construct a string with names and aliases from the arrays formatted as:
 * "name (alias), name, name (alias), name, name"
 *
 * Returns: string; the caller is responsible for freeing it.
 */
static char *
get_valid_options_string (const NameItem *array, const NameItem *array_slv)
{
	const NameItem *iter = array;
	GString *str;
	int i;

	str = g_string_sized_new (150);

	for (i = 0; i < 2; i++, iter = array_slv) {
		while (iter && iter->name) {
			if (str->len)
				g_string_append (str, ", ");
			if (iter->alias)
				g_string_append_printf (str, "%s (%s)", iter->name, iter->alias);
			else
				g_string_append (str, iter->name);
			iter++;
		}
	}
	return g_string_free (str, FALSE);
}

static const NameItem *
get_valid_settings_array (const char *con_type)
{
	guint i, num;

	/* No connection type yet? Return settings for a generic connection
	 * (just the "connection" setting), which always makes sense. */
	if (!con_type)
		return nmc_valid_connection_types[0].settings;

	num = G_N_ELEMENTS (nmc_valid_connection_types);
	for (i = 0; i < num; i++) {
		if (nm_streq0 (con_type, nmc_valid_connection_types[i].name))
			return nmc_valid_connection_types[i].settings;
	}

	return NULL;
}

/* get_valid_properties_string:
 * @array: base properties for the current connection type
 * @array_slv: slave properties (or ipv4/ipv6 ones) for the current connection type
 * @modifier: to prepend to each element of the returned list
 * @prefix: only properties matching the prefix will be returned
 * @postfix: required prefix on the property args; if a empty string is passed, is
 *           assumed that the @prefix is a shortcut, so it should not be completed
 *           but left as is (and an additional check for shortcut ambiguity is performed)
 *
 * Returns a list of properties compatible with the current connection type
 * for the shell autocompletion functionality.
 *
 * Returns: list of property.arg elements
 */
static char *
get_valid_properties_string (const NameItem *array,
                             const NameItem *array_slv,
                             char modifier,
                             const char *prefix,
                             const char *postfix)
{
	const NameItem *iter = array;
	const NmcOutputField *field_iter;
	const char *prop_name = NULL;
	GString *str;
	int i, j;
	gboolean full_match = FALSE;

	g_return_val_if_fail (prefix, NULL);

	str = g_string_sized_new (1024);

	for (i = 0; i < 2; i++, iter = array_slv) {
		while (!full_match && iter && iter->name) {
			if (   !(g_str_has_prefix (iter->name, prefix))
			    && (!(iter->alias) || !g_str_has_prefix (iter->alias, prefix))) {
				iter++;
				continue;
			}
			/* If postix (so prefix is terminated by a dot), check
			 * that prefix is not ambiguous */
			if (postfix) {
				/* If we have a perfect match, no need to look for others
				 * prefix and no check on ambiguity should be performed.
				 * Moreover, erase previous matches from output string */
				if (   nm_streq (prefix, iter->name)
				    || nm_streq0 (prefix, iter->alias)) {
					g_string_erase (str, 0, -1);
					full_match = TRUE;
				} else if (prop_name) {
					return g_string_free (str, TRUE);
				}
				prop_name = prefix;
			} else {
				prop_name = iter->name;
			}

			/* Search the array with the arguments of the current property */
			j = 0;
			while (!nm_streq0 (iter->name, nmc_fields_settings_names[j].name)) {
				g_assert (nmc_fields_settings_names[j].name);
				j++;
			}
			field_iter = nmc_fields_settings_names[j].group;

			j = 0;
			while (field_iter[j].name) {
				gchar *new;
				const char *arg_name = field_iter[j].name;

				/* If required, expand the alias too */
				if (!postfix && iter->alias) {
					if (modifier)
						g_string_append_c (str, modifier);
					new = g_strdup_printf ("%s.%s\n",
							       iter->alias,
							       arg_name);
					g_string_append (str, new);
					g_free (new);
				}

				if (postfix && !g_str_has_prefix (arg_name, postfix)) {
					j++;
					continue;
				}

				if (modifier)
					g_string_append_c (str, modifier);
				new = g_strdup_printf ("%s.%s\n",
						       prop_name,
						       arg_name);
				g_string_append (str, new);
				g_free (new);
				j++;
			}
			iter++;
		}
	}
	return g_string_free (str, FALSE);
}

/*
 * Check if 'val' is valid string in either array->name or array->alias for
 * both array parameters (array & array_slv).
 * It accepts shorter string provided they are not ambiguous.
 * 'val' == NULL doesn't hurt.
 *
 * Returns: pointer to array->name string or NULL on failure.
 * The returned string must not be freed.
 */
static const char *
check_valid_name (const char *val, const NameItem *array, const NameItem *array_slv, GError **error)
{
	const NameItem *iter;
	gs_unref_ptrarray GPtrArray *tmp_arr = NULL;
	const char *str;
	GError *tmp_err = NULL;
	int i;

	g_return_val_if_fail (array, NULL);

	/* Create a temporary array that can be used in nmc_string_is_valid() */
	tmp_arr = g_ptr_array_sized_new (32);
	iter = array;
	for (i = 0; i < 2; i++, iter = array_slv) {
		while (iter && iter->name) {
			g_ptr_array_add (tmp_arr, (gpointer) iter->name);
			if (iter->alias)
				g_ptr_array_add (tmp_arr, (gpointer) iter->alias);
			iter++;
		}
	}
	g_ptr_array_add (tmp_arr, (gpointer) NULL);

	/* Check string validity */
	str = nmc_string_is_valid (val, (const char **) tmp_arr->pdata, &tmp_err);
	if (!str) {
		if (tmp_err->code == 1)
			g_propagate_error (error, tmp_err);
		else {
			/* We want to handle aliases, so construct own error message */
			char *err_str = get_valid_options_string (array, array_slv);

			g_set_error (error, 1, 0, _("'%s' not among [%s]"), val, err_str);
			g_free (err_str);
			g_clear_error (&tmp_err);
		}
		return NULL;
	}

	/* Return a pointer to the found string in passed 'array' */
	iter = array;
	for (i = 0; i < 2; i++, iter = array_slv) {
		while (iter && iter->name) {
			if (   nm_streq (iter->name, str)
			    || nm_streq0 (iter->alias, str)) {
				return iter->name;
			}
			iter++;
		}
	}

	/* We should not really come here */
	g_set_error (error, 1, 0, _("Unknown error"));
	return NULL;
}

static gboolean
is_setting_mandatory (NMConnection *connection, NMSetting *setting)
{
	NMSettingConnection *s_con;
	const char *c_type;
	const NameItem *item;
	const char *name;
	const char *s_type;
	char *slv_type;

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

	/* Let's give a try to parameters related to slave type */
	s_type = nm_setting_connection_get_slave_type (s_con);
	slv_type = g_strdup_printf ("%s-slave", s_type ? s_type : "no");
	item = get_valid_settings_array (slv_type);
	g_free (slv_type);
	while (item && item->name) {
		if (!strcmp (name, item->name))
			return item->mandatory;
		item++;
	}

	return FALSE;
}

/*----------------------------------------------------------------------------*/

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

/* normalized_master_for_slave:
 * @connections: list af all connections
 * @master: UUID, ifname or ID of the master connection
 * @type: virtual connection type (bond, team, bridge, ...) or %NULL
 * @out_type: type of the connection that matched
 *
 * Check whether master is a valid interface name, UUID or ID of some connection,
 * possibly of a specified @type.
 * First UUID and ifname are checked. If they don't match, ID is checked
 * and replaced by UUID on a match.
 *
 * Returns: identifier of master connection if found, %NULL otherwise
 */
static const char *
normalized_master_for_slave (const GPtrArray *connections,
                             const char *master,
                             const char *type,
                             const char **out_type)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	const char *con_type = NULL, *id, *uuid, *ifname;
	int i;
	const char *found_by_id = NULL;
	const char *out_type_by_id = NULL;
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
		if (type && g_strcmp0 (con_type, type) != 0)
			continue;
		if (func) {
			/* There was a prefix; only compare to that type. */
			if (g_strcmp0 (master, func (connection)) == 0) {
				if (out_type)
					*out_type = con_type;
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
				if (out_type)
					*out_type = con_type;
				break;
			}
			if (!found_by_id && g_strcmp0 (master, id) == 0) {
				out_type_by_id = con_type;
				found_by_id = uuid;
			}
		}
	}

	if (!out_master) {
		out_master = found_by_id;
		if (out_type)
			*out_type = out_type_by_id;
	}

	if (!out_master) {
		g_print (_("Warning: master='%s' doesn't refer to any existing profile.\n"), master);
		out_master = master;
		if (out_type)
			*out_type = type;
	}

	return out_master;
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

static NMSetting *
is_setting_valid (NMConnection *connection, const NameItem *valid_settings_main, const NameItem *valid_settings_slave, char *setting)
{
	const char *setting_name;

	if (!(setting_name = check_valid_name (setting, valid_settings_main, valid_settings_slave, NULL)))
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

static void
set_default_interface_name (NmCli *nmc, NMSettingConnection *s_con)
{
	char *ifname = NULL;
	const char *con_type = nm_setting_connection_get_connection_type (s_con);

	if (nm_setting_connection_get_interface_name (s_con))
		return;

	/* Set a sensible bond/team/bridge interface name by default */
	if (g_strcmp0 (con_type, NM_SETTING_BOND_SETTING_NAME) == 0)
		ifname = unique_master_iface_ifname (nmc->connections, "nm-bond");
	else if (g_strcmp0 (con_type, NM_SETTING_TEAM_SETTING_NAME) == 0)
		ifname = unique_master_iface_ifname (nmc->connections, "nm-team");
	else if (g_strcmp0 (con_type, NM_SETTING_BRIDGE_SETTING_NAME) == 0)
		ifname = unique_master_iface_ifname (nmc->connections, "nm-bridge");
	else
		return;

	g_object_set (s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, ifname, NULL);
	g_free (ifname);
}

/*----------------------------------------------------------------------------*/

static OptionInfo option_info[];

/*
 * Mark options in option_info as relevant.
 * The questionnaire (for --ask) will ask for them.
 */
static void
enable_options (const gchar *setting_name, const gchar *property, const gchar * const *opts)
{
	OptionInfo *candidate;

	for (candidate = option_info; candidate->setting_name; candidate++) {
		if (   strcmp (candidate->setting_name, setting_name) == 0
		    && strcmp (candidate->property, property) == 0
		    && (candidate->flags & OPTION_DONT_ASK)
		    && candidate->option
		    && g_strv_contains (opts, candidate->option)) {
			candidate->flags |= OPTION_ENABLED;
		}
	}
}

/*
 * Mark options in option_info as irrelevant (because we learned they make no sense
 * or they have been set via different means).
 * The questionnaire (for --ask) will not ask for them.
 */
static void
disable_options (const gchar *setting_name, const gchar *property)
{
	OptionInfo *candidate;

	for (candidate = option_info; candidate->setting_name; candidate++) {
		if (   strcmp (candidate->setting_name, setting_name) == 0
		    && (!property || strcmp (candidate->property, property) == 0))
		candidate->flags |= OPTION_DISABLED;
	}
}

/*
 * Reset marks done with enable_options() and disable_options().
 * Ensures correct operation in case more than one connection is added in a single
 * nmcli session.
 */
static void
reset_options (void)
{
	OptionInfo *candidate;

	for (candidate = option_info; candidate->setting_name; candidate++) {
		candidate->flags &= ~OPTION_DISABLED;
		candidate->flags &= ~OPTION_ENABLED;
	}
}

static gboolean
set_property (NMConnection *connection,
              const char *setting_name, const char *property, const char *value,
              char modifier, GError **error)
{
	gs_free char *property_name = NULL, *value_free = NULL;
	NMSetting *setting;
	GError *local = NULL;

	setting = nm_connection_get_setting_by_name (connection, setting_name);
	if (!setting) {
		setting = nmc_setting_new_for_name (setting_name);
		if (!setting) {
			/* This should really not happen */
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_UNKNOWN,
			             _("Error: don't know how to create '%s' setting."),
			             setting_name);
			return FALSE;
		}
		nmc_setting_custom_init (setting);
		nm_connection_add_setting (connection, setting);
	}

	property_name = is_property_valid (setting, property, &local);
	if (!property_name) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: invalid property '%s': %s."),
		             property, local->message);
		g_clear_error (&local);
		return FALSE;
	}

	if (modifier != '-') {
		/* Set/add value */
		if (modifier != '+') {
			/* We allow the existing property value to be passed as parameter,
			 * so make a copy if we are going to free it.
			 */
			value = value_free = g_strdup (value);
			nmc_setting_reset_property (setting, property_name, NULL);
		}
		if (!nmc_setting_set_property (setting, property_name, value, &local)) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("Error: failed to modify %s.%s: %s."),
			             setting_name, property, local->message);
			g_clear_error (&local);
			return FALSE;
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
				nmc_setting_remove_property_option (setting, property_name, NULL, idx, &local);
			else
				nmc_setting_remove_property_option (setting, property_name, value, 0, &local);
			if (local) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: failed to remove a value from %s.%s: %s."),
				             setting_name, property,  local->message);
				g_clear_error (&local);
				return FALSE;
			}
		} else
			nmc_setting_reset_property (setting, property_name, NULL);
	}

	/* Don't ask for this property in interactive mode. */
	disable_options (setting_name, property_name);

	return TRUE;
}

static gboolean
set_option (NmCli *nmc, NMConnection *connection, OptionInfo *option, const gchar *value, GError **error)
{
	option->flags |= OPTION_DISABLED;
	if (option->check_and_set) {
		return option->check_and_set (nmc, connection, option, value, error);
	} else if (value) {
		return set_property (connection, option->setting_name, option->property,
		                     value, option->flags & OPTION_MULTI ? '+' : '\0', error);
	} else if (option->flags & OPTION_REQD) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
	                     _("Error: '%s' is mandatory."), option->option);
		return FALSE;
	}

	return TRUE;
}

/*
 * Return relevant NameItem[] tables for given connection (based on connection type
 * and slave type.
 */
static gboolean
con_settings (NMConnection *connection, const NameItem **type_settings, const NameItem **slv_settings, GError **error)
{
	const char *con_type;
	gs_free char *slv_type = NULL;
	NMSettingConnection *s_con;

	g_return_val_if_fail (type_settings, FALSE);
	g_return_val_if_fail (slv_settings, FALSE);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	con_type = nm_setting_connection_get_slave_type (s_con);
	if (!con_type)
		con_type = "no";
	slv_type = g_strdup_printf ("%s-slave", con_type);
	if (slv_type) {
		*slv_settings = get_valid_settings_array (slv_type);
		if (!*slv_settings) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("Error: invalid slave type; %s."), slv_type);
			return FALSE;
		}
	} else {
		*slv_settings = NULL;
	}

	con_type = nm_setting_connection_get_connection_type (s_con);
	if (!con_type)
		con_type = NM_SETTING_GENERIC_SETTING_NAME;
	*type_settings = get_valid_settings_array (con_type);
	if (!*type_settings) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: invalid connection type; %s."), con_type);
		return FALSE;
	}

	return TRUE;
}

/*
 * Make sure all required settings are in place (should be called when
 * it's possible that a type is aready set).
 */
static void
ensure_settings (NMConnection *connection, const NameItem *item)
{
	const NameItem *setting_item;
	NMSetting *setting;

	for (setting_item = item; setting_item->name; setting_item++) {
		if (!setting_item->mandatory)
			continue;
		if (nm_connection_get_setting_by_name (connection, setting_item->name))
			continue;
		setting = nmc_setting_new_for_name (setting_item->name);
		if (setting) {
			nmc_setting_custom_init (setting);
			nm_connection_add_setting (connection, setting);
		}
	}
}

/*----------------------------------------------------------------------------*/

static char *
gen_func_slave_type (const char *text, int state)
{
	const char *words[] = { "bond", "team", "bridge", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_func_vpn_types (const char *text, int state)
{
	gs_strfreev char **plugin_names = NULL;

	plugin_names = nm_vpn_plugin_info_list_get_service_types (nm_vpn_get_plugin_infos (), FALSE, TRUE);
	return nmc_rl_gen_func_basic (text, state, (const char **) plugin_names);
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
gen_func_bond_lacp_rate (const char *text, int state)
{
	const char *words[] = { "slow", "fast", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_func_adsl_proto (const char *text, int state)
{
	const char *words[] = { "pppoe", "pppoa", "ipoatm", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_func_adsl_encap (const char *text, int state)
{
	const char *words[] = { "vcmux", "llc", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_func_tun_mode (const char *text, int state)
{
	const char *words[] = { "tun", "tap", NULL };
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_func_ip_tunnel_mode (const char *text, int state)
{
	gs_free const char **words = NULL;

	words = nm_utils_enum_get_values (nm_ip_tunnel_mode_get_type (),
	                                  NM_IP_TUNNEL_MODE_UNKNOWN + 1,
	                                  G_MAXINT);
	return nmc_rl_gen_func_basic (text, state, words);
}

static char *
gen_func_macvlan_mode (const char *text, int state)
{
	gs_free const char **words = NULL;

	words = nm_utils_enum_get_values (nm_setting_macvlan_mode_get_type(),
	                                  NM_SETTING_MACVLAN_MODE_UNKNOWN + 1,
	                                  G_MAXINT);
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


/*----------------------------------------------------------------------------*/

static gboolean
set_connection_type (NmCli *nmc, NMConnection *con, OptionInfo *option, const char *value, GError **error)
{
	const NameItem *type_settings, *slv_settings;
	GError *local = NULL;
	const gchar *master[] = { "master", NULL };

	value = check_valid_name (value, nmc_valid_connection_types, NULL, &local);
	if (!value) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: bad connection type: %s."), local->message);
		g_clear_error (&local);
		return FALSE;
	}

	if (g_strcmp0 (value, "bond-slave") == 0) {
		value = NM_SETTING_WIRED_SETTING_NAME;
		if (!set_property (con, NM_SETTING_CONNECTION_SETTING_NAME,
		                   NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BOND_SETTING_NAME,
		                   '\0', error)) {
			return FALSE;
		}
		enable_options (NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_MASTER, master);
	} else if (g_strcmp0 (value, "bridge-slave") == 0) {
		value = NM_SETTING_WIRED_SETTING_NAME;
		if (!set_property (con, NM_SETTING_CONNECTION_SETTING_NAME,
		                   NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BRIDGE_SETTING_NAME,
		                   '\0', error)) {
			return FALSE;
		}
		enable_options (NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_MASTER, master);
	} else if (g_strcmp0 (value, "team-slave") == 0) {
		value = NM_SETTING_WIRED_SETTING_NAME;
		if (!set_property (con, NM_SETTING_CONNECTION_SETTING_NAME,
		                   NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_TEAM_SETTING_NAME,
		                   '\0', error)) {
			return FALSE;
		}
		enable_options (NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_MASTER, master);
	}

	/* ifname is mandatory for all connection types except virtual ones (bond, team, bridge, vlan) */
	if (   (strcmp (value, NM_SETTING_BOND_SETTING_NAME) == 0)
	    || (strcmp (value, NM_SETTING_TEAM_SETTING_NAME) == 0)
	    || (strcmp (value, NM_SETTING_BRIDGE_SETTING_NAME) == 0)
	    || (strcmp (value, NM_SETTING_VLAN_SETTING_NAME) == 0)) {
		disable_options (NM_SETTING_CONNECTION_SETTING_NAME,
		                 NM_SETTING_CONNECTION_INTERFACE_NAME);
	}

	if (!set_property (con, option->setting_name, option->property, value, '\0', error))
		return FALSE;

	if (!con_settings (con, &type_settings, &slv_settings, error))
		return FALSE;

	ensure_settings (con, slv_settings);
	ensure_settings (con, type_settings);

	return TRUE;
}

static gboolean
set_connection_iface (NmCli *nmc, NMConnection *con, OptionInfo *option, const char *value, GError **error)
{
	if (value) {
		if (!nm_utils_iface_valid_name (value) && strcmp (value, "*") != 0) {
			g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("Error: '%s' is not a valid interface nor '*'."),
			             value);
			return FALSE;
		}
		/* Special value of '*' means no specific interface name */
		if (strcmp (value, "*") == 0)
			value = NULL;
	}

	return set_property (con, option->setting_name, option->property, value, '\0', error);
}

static gboolean
set_connection_master (NmCli *nmc, NMConnection *con, OptionInfo *option, const char *value, GError **error)
{
	NMSettingConnection *s_con;
	const char *slave_type;

	s_con = nm_connection_get_setting_connection (con);
	g_return_val_if_fail (s_con, FALSE);

	if (!value) {
		g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			             _("Error: master is required"));
		return FALSE;
	}

	slave_type = nm_setting_connection_get_slave_type (s_con);
	value = normalized_master_for_slave (nmc->connections, value, slave_type, &slave_type);

	if (!set_property (con, NM_SETTING_CONNECTION_SETTING_NAME,
	                   NM_SETTING_CONNECTION_SLAVE_TYPE, slave_type,
	                   '\0', error)) {
		return FALSE;
	}

	return set_property (con, option->setting_name, option->property, value, '\0', error);
}

static gboolean
set_bond_option (NmCli *nmc, NMConnection *con, OptionInfo *option, const char *value, GError **error)
{
	NMSettingBond *s_bond;
	gboolean success;

	s_bond = nm_connection_get_setting_bond (con);
	g_return_val_if_fail (s_bond, FALSE);

	if (!value)
		return TRUE;

	if (strcmp (option->option, "mode") == 0) {
		value = nmc_bond_validate_mode (value, error);
		if (!value)
			return FALSE;

		if (g_strcmp0 (value, "active-backup") == 0) {
			const gchar *primary[] = { "primary", NULL };
			enable_options (NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS, primary);
		}

		success = nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MODE, value);
	} else if (strcmp (option->option, "primary") == 0)
		success = nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_PRIMARY, value);
	else if (strcmp (option->option, "miimon") == 0)
		success = nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MIIMON, value);
	else if (strcmp (option->option, "downdelay") == 0)
		success = nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY, value);
	else if (strcmp (option->option, "updelay") == 0)
		success = nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_UPDELAY, value);
	else if (strcmp (option->option, "arp-interval") == 0)
		success = nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ARP_INTERVAL, value);
	else if (strcmp (option->option, "arp-ip-target") == 0)
		success = nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ARP_IP_TARGET, value);
	else if (strcmp (option->option, "lacp-rate") == 0)
		success = nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_LACP_RATE, value);
	else
		g_return_val_if_reached (FALSE);

	if (!success) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: error adding bond option '%s=%s'."),
		             option->option, value);
	}

	return success;
}

static gboolean
set_bond_monitoring_mode (NmCli *nmc, NMConnection *con, OptionInfo *option, const char *value, GError **error)
{
	NMSettingBond *s_bond;
	gs_free gchar *monitor_mode = NULL;
	const gchar *miimon_opts[] = { "miimon", "downdelay", "updelay", NULL };
	const gchar *arp_opts[] = { "arp-interval", "arp-ip-target", NULL };

	s_bond = nm_connection_get_setting_bond (con);
	g_return_val_if_fail (s_bond, FALSE);

	if (value) {
		monitor_mode = g_strdup (value);
		g_strstrip (monitor_mode);
	} else {
		monitor_mode = g_strdup (WORD_MIIMON);
	}

	if (matches (monitor_mode, WORD_MIIMON) == 0)
		enable_options (NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS, miimon_opts);
	else if (matches (monitor_mode, WORD_ARP) == 0)
		enable_options (NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_OPTIONS, arp_opts);
	else {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: '%s' is not a valid monitoring mode; use '%s' or '%s'.\n"),
		             monitor_mode, WORD_MIIMON, WORD_ARP);
		return FALSE;
	}

	return TRUE;
}

static gboolean
set_bluetooth_type (NmCli *nmc, NMConnection *con, OptionInfo *option, const char *value, GError **error)
{
	NMSetting *setting;

	if (!value)
		return TRUE;

	/* 'dun' type requires adding 'gsm' or 'cdma' setting */
	if (   !strcmp (value, NM_SETTING_BLUETOOTH_TYPE_DUN)
	    || !strcmp (value, NM_SETTING_BLUETOOTH_TYPE_DUN"-gsm")) {
		value = NM_SETTING_BLUETOOTH_TYPE_DUN;
		setting = nm_setting_gsm_new ();
		nmc_setting_custom_init (setting);
		nm_connection_add_setting (con, setting);
	} else if (!strcmp (value, NM_SETTING_BLUETOOTH_TYPE_DUN"-cdma")) {
		value = NM_SETTING_BLUETOOTH_TYPE_DUN;
		setting = nm_setting_cdma_new ();
		nm_connection_add_setting (con, setting);
	} else if (!strcmp (value, NM_SETTING_BLUETOOTH_TYPE_PANU)) {
		/* no op */
	} else {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: 'bt-type': '%s' not valid; use [%s, %s (%s), %s]."),
		             value, NM_SETTING_BLUETOOTH_TYPE_PANU, NM_SETTING_BLUETOOTH_TYPE_DUN,
		             NM_SETTING_BLUETOOTH_TYPE_DUN"-gsm", NM_SETTING_BLUETOOTH_TYPE_DUN"-cdma");
		return FALSE;
	}

	return set_property (con, option->setting_name, option->property, value, '\0', error);
}

static gboolean
set_yes_no (NmCli *nmc, NMConnection *con, OptionInfo *option, const char *value, GError **error)
{
	if (g_strcmp0 (value, _(WORD_LOC_YES)))
		value = WORD_YES;
	if (g_strcmp0 (value, _(WORD_LOC_NO)))
		value = WORD_NO;

	return set_property (con, option->setting_name, option->property, value, '\0', error);
}

static gboolean
set_ip4_address (NmCli *nmc, NMConnection *con, OptionInfo *option, const char *value, GError **error)
{
	NMSettingIPConfig *s_ip4;

	if (!value)
		return TRUE;

	s_ip4 = nm_connection_get_setting_ip4_config (con);
	if (!s_ip4) {
		s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
		nm_connection_add_setting (con, NM_SETTING (s_ip4));
		g_object_set (s_ip4,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
		              NULL);
	}
	return set_property (con, option->setting_name, option->property, value, '\0', error);
}

static gboolean
set_ip6_address (NmCli *nmc, NMConnection *con, OptionInfo *option, const char *value, GError **error)
{
	NMSettingIPConfig *s_ip6;

	if (!value)
		return TRUE;

	s_ip6 = nm_connection_get_setting_ip6_config (con);
	if (!s_ip6) {
		s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
		nm_connection_add_setting (con, NM_SETTING (s_ip6));
		g_object_set (s_ip6,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
		              NULL);
	}
	return set_property (con, option->setting_name, option->property, value, '\0', error);
}


/*----------------------------------------------------------------------------*/

static OptionInfo option_info[] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME,   NM_SETTING_CONNECTION_TYPE,             "type",         OPTION_REQD, PROMPT_CON_TYPE, NULL,
                                                                                                        set_connection_type, gen_connection_types },
	{ NM_SETTING_CONNECTION_SETTING_NAME,   NM_SETTING_CONNECTION_ID,               "con-name",     OPTION_DONT_ASK, NULL, NULL, NULL, NULL },
	{ NM_SETTING_CONNECTION_SETTING_NAME,   NM_SETTING_CONNECTION_AUTOCONNECT,      "autoconnect",  OPTION_DONT_ASK, NULL, NULL, NULL,
                                                                                                        gen_func_bool_values_l10n },
	{ NM_SETTING_CONNECTION_SETTING_NAME,   NM_SETTING_CONNECTION_INTERFACE_NAME,   "ifname",       OPTION_REQD, PROMPT_IFNAME, NULL,
                                                                                                        set_connection_iface, nmc_rl_gen_func_ifnames },
	{ NM_SETTING_CONNECTION_SETTING_NAME,   NM_SETTING_CONNECTION_MASTER,           "master",       OPTION_DONT_ASK, PROMPT_MASTER, NULL,
                                                                                                        set_connection_master, gen_func_master_ifnames },
	{ NM_SETTING_CONNECTION_SETTING_NAME,   NM_SETTING_CONNECTION_SLAVE_TYPE,       "slave-type",   OPTION_DONT_ASK, NULL, NULL, NULL,
                                                                                                        gen_func_slave_type },
	{ NM_SETTING_PPPOE_SETTING_NAME,        NM_SETTING_PPPOE_USERNAME,              "username",     OPTION_REQD, N_("PPPoE username"), NULL, NULL, NULL },
	{ NM_SETTING_PPPOE_SETTING_NAME,        NM_SETTING_PPPOE_PASSWORD,              "password",     OPTION_NONE, N_("Password [none]"), NULL, NULL, NULL },
	{ NM_SETTING_PPPOE_SETTING_NAME,        NM_SETTING_PPPOE_SERVICE,               "service",      OPTION_NONE, N_("Service [none]"), NULL, NULL, NULL },
	{ NM_SETTING_WIRED_SETTING_NAME,        NM_SETTING_WIRED_MTU,                   "mtu",          OPTION_NONE, N_("MTU [auto]"), NULL, NULL, NULL },
	{ NM_SETTING_WIRED_SETTING_NAME,        NM_SETTING_WIRED_MAC_ADDRESS,           "mac",          OPTION_NONE, N_("MAC [none]"), NULL, NULL, NULL },
	{ NM_SETTING_WIRED_SETTING_NAME,        NM_SETTING_WIRED_CLONED_MAC_ADDRESS,    "cloned-mac",   OPTION_NONE, N_("Cloned MAC [none]"), NULL, NULL, NULL },
	{ NM_SETTING_INFINIBAND_SETTING_NAME,   NM_SETTING_INFINIBAND_MTU,              "mtu",          OPTION_NONE, N_("MTU [auto]"), NULL, NULL, NULL },
	{ NM_SETTING_INFINIBAND_SETTING_NAME,   NM_SETTING_INFINIBAND_MAC_ADDRESS,      "mac",          OPTION_NONE, N_("MAC [none]"), NULL, NULL, NULL },
	{ NM_SETTING_INFINIBAND_SETTING_NAME,   NM_SETTING_INFINIBAND_TRANSPORT_MODE,   "transport-mode", OPTION_NONE, PROMPT_IB_MODE, PROMPT_IB_MODE_CHOICES,
                                                                                                        NULL, gen_func_ib_type },
	{ NM_SETTING_INFINIBAND_SETTING_NAME,   NM_SETTING_INFINIBAND_PARENT,           "parent",       OPTION_NONE, N_("Parent interface [none]"), NULL, NULL, NULL },
	{ NM_SETTING_INFINIBAND_SETTING_NAME,   NM_SETTING_INFINIBAND_P_KEY,            "p-key",        OPTION_NONE, N_("P_KEY [none]"), NULL, NULL, NULL },
	{ NM_SETTING_WIRELESS_SETTING_NAME,     NM_SETTING_WIRELESS_SSID,               "ssid",         OPTION_REQD, N_("SSID"), NULL, NULL, NULL },
	{ NM_SETTING_WIRELESS_SETTING_NAME,     NM_SETTING_WIRELESS_MODE,               "mode",         OPTION_NONE, PROMPT_WIFI_MODE, PROMPT_WIFI_MODE_CHOICES,
                                                                                                        NULL, gen_func_wifi_mode },
	{ NM_SETTING_WIRELESS_SETTING_NAME,     NM_SETTING_WIRELESS_MTU,                "mtu",          OPTION_NONE, N_("MTU [auto]"), NULL, NULL, NULL },
	{ NM_SETTING_WIRELESS_SETTING_NAME,     NM_SETTING_WIRELESS_MAC_ADDRESS,        "mac",          OPTION_NONE, N_("MAC [none]"), NULL, NULL, NULL },
	{ NM_SETTING_WIRELESS_SETTING_NAME,     NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, "cloned-mac",   OPTION_NONE, N_("Cloned MAC [none]"), NULL, NULL, NULL },
	{ NM_SETTING_WIMAX_SETTING_NAME,        NM_SETTING_WIMAX_NETWORK_NAME,          "nsp",          OPTION_REQD, N_("WiMAX NSP name"), NULL, NULL, NULL },
	{ NM_SETTING_WIMAX_SETTING_NAME,        NM_SETTING_WIMAX_MAC_ADDRESS,           "mac",          OPTION_NONE, N_("MAC [none]"), NULL, NULL, NULL },
	{ NM_SETTING_GSM_SETTING_NAME,          NM_SETTING_GSM_APN,                     "apn",          OPTION_REQD, N_("APN"), NULL, NULL, NULL },
	{ NM_SETTING_GSM_SETTING_NAME,          NM_SETTING_GSM_USERNAME,                "user",         OPTION_NONE, N_("Username [none]"), NULL, NULL, NULL },
	{ NM_SETTING_GSM_SETTING_NAME,          NM_SETTING_GSM_PASSWORD,                "password",     OPTION_NONE, N_("Password [none]"), NULL, NULL, NULL },
	{ NM_SETTING_CDMA_SETTING_NAME,         NM_SETTING_CDMA_USERNAME,               "user",         OPTION_NONE, N_("Username [none]"), NULL, NULL, NULL },
	{ NM_SETTING_CDMA_SETTING_NAME,         NM_SETTING_CDMA_PASSWORD,               "password",     OPTION_NONE, N_("Password [none]"), NULL, NULL, NULL },
	{ NM_SETTING_BLUETOOTH_SETTING_NAME,    NM_SETTING_BLUETOOTH_BDADDR,            "addr",         OPTION_REQD, N_("Bluetooth device address"), NULL, NULL, NULL },
	{ NM_SETTING_BLUETOOTH_SETTING_NAME,    NM_SETTING_BLUETOOTH_TYPE,              "bt-type",      OPTION_NONE, PROMPT_BT_TYPE, PROMPT_BT_TYPE_CHOICES,
                                                                                                        set_bluetooth_type, gen_func_bt_type },
	{ NM_SETTING_VLAN_SETTING_NAME,         NM_SETTING_VLAN_PARENT,                 "dev",          OPTION_REQD, N_("VLAN parent device or connection UUID"), NULL,
                                                                                                        NULL, nmc_rl_gen_func_ifnames },
	{ NM_SETTING_VLAN_SETTING_NAME,         NM_SETTING_VLAN_ID,                     "id",           OPTION_REQD, N_("VLAN ID (<0-4094>)"), NULL, NULL, NULL },
	{ NM_SETTING_VLAN_SETTING_NAME,         NM_SETTING_VLAN_FLAGS,                  "flags",        OPTION_NONE, N_("VLAN flags (<0-7>) [none]"), NULL, NULL, NULL },
	{ NM_SETTING_VLAN_SETTING_NAME,         NM_SETTING_VLAN_INGRESS_PRIORITY_MAP,   "ingress",      OPTION_NONE, N_("Ingress priority maps [none]"), NULL, NULL, NULL },
	{ NM_SETTING_VLAN_SETTING_NAME,         NM_SETTING_VLAN_EGRESS_PRIORITY_MAP,    "egress",       OPTION_NONE, N_("Egress priority maps [none]"), NULL, NULL, NULL },
	{ NM_SETTING_BOND_SETTING_NAME,         NM_SETTING_BOND_OPTIONS,                "mode",         OPTION_NONE, PROMPT_BOND_MODE, "[balance-rr]",
                                                                                                        set_bond_option, gen_func_bond_mode },
	{ NM_SETTING_BOND_SETTING_NAME,         NM_SETTING_BOND_OPTIONS,                "primary",      OPTION_DONT_ASK, N_("Bonding primary interface [none]"),
                                                                                                        NULL, set_bond_option, nmc_rl_gen_func_ifnames },
	{ NM_SETTING_BOND_SETTING_NAME,         NM_SETTING_BOND_OPTIONS,                NULL,           OPTION_NONE, N_("Bonding monitoring mode"), PROMPT_BOND_MON_MODE_CHOICES,
                                                                                                        set_bond_monitoring_mode, gen_func_bond_mon_mode },
	{ NM_SETTING_BOND_SETTING_NAME,         NM_SETTING_BOND_OPTIONS,                "miimon",       OPTION_DONT_ASK, N_("Bonding miimon [100]"), NULL, set_bond_option, NULL },
	{ NM_SETTING_BOND_SETTING_NAME,         NM_SETTING_BOND_OPTIONS,                "downdelay",    OPTION_DONT_ASK, N_("Bonding downdelay [0]"), NULL, set_bond_option, NULL },
	{ NM_SETTING_BOND_SETTING_NAME,         NM_SETTING_BOND_OPTIONS,                "updelay",      OPTION_DONT_ASK, N_("Bonding updelay [0]"), NULL, set_bond_option, NULL },
	{ NM_SETTING_BOND_SETTING_NAME,         NM_SETTING_BOND_OPTIONS,                "arp-interval", OPTION_DONT_ASK, N_("Bonding arp-interval [0]"), NULL,
                                                                                                        set_bond_option, NULL },
	{ NM_SETTING_BOND_SETTING_NAME,         NM_SETTING_BOND_OPTIONS,                "arp-ip-target", OPTION_DONT_ASK, N_("Bonding arp-ip-target [none]"),
                                                                                                        NULL, set_bond_option, NULL },
	{ NM_SETTING_BOND_SETTING_NAME,         NM_SETTING_BOND_OPTIONS,                "lacp-rate",    OPTION_DONT_ASK, N_("LACP rate ('slow' or 'fast') [slow]"), NULL,
                                                                                                        set_bond_option, gen_func_bond_lacp_rate },
	{ NM_SETTING_TEAM_SETTING_NAME,         NM_SETTING_TEAM_CONFIG,                 "config",       OPTION_NONE, N_("Team JSON configuration [none]"), NULL, NULL, NULL },
	{ NM_SETTING_TEAM_PORT_SETTING_NAME,    NM_SETTING_TEAM_PORT_CONFIG,            "config",       OPTION_NONE, N_("Team JSON configuration [none]"), NULL, NULL, NULL },
	{ NM_SETTING_BRIDGE_SETTING_NAME,       NM_SETTING_BRIDGE_STP,                  "stp",          OPTION_NONE, N_("Enable STP [no]"), NULL,
                                                                                                        set_yes_no, gen_func_bool_values_l10n },
	{ NM_SETTING_BRIDGE_SETTING_NAME,       NM_SETTING_BRIDGE_PRIORITY,             "priority",     OPTION_NONE, N_("STP priority [32768]"), NULL, NULL, NULL },
	{ NM_SETTING_BRIDGE_SETTING_NAME,       NM_SETTING_BRIDGE_FORWARD_DELAY,        "forward-delay", OPTION_NONE, N_("Forward delay [15]"), NULL, NULL, NULL },
	{ NM_SETTING_BRIDGE_SETTING_NAME,       NM_SETTING_BRIDGE_HELLO_TIME,           "hello-time",   OPTION_NONE, N_("Hello time [2]"), NULL, NULL, NULL },
	{ NM_SETTING_BRIDGE_SETTING_NAME,       NM_SETTING_BRIDGE_MAX_AGE,              "max-age",      OPTION_NONE, N_("Max age [20]"), NULL, NULL, NULL },
	{ NM_SETTING_BRIDGE_SETTING_NAME,       NM_SETTING_BRIDGE_AGEING_TIME,          "ageing-time",  OPTION_NONE, N_("MAC address ageing time [300]"), NULL, NULL, NULL },
	{ NM_SETTING_BRIDGE_SETTING_NAME,       NM_SETTING_BRIDGE_MULTICAST_SNOOPING,   "multicast-snooping", OPTION_NONE, N_("Enable IGMP snooping [no]"), NULL,
                                                                                                        set_yes_no, gen_func_bool_values_l10n },
	{ NM_SETTING_BRIDGE_SETTING_NAME,       NM_SETTING_BRIDGE_MAC_ADDRESS,          "mac",          OPTION_NONE, N_("MAC [none]"), NULL, NULL, NULL },
	{ NM_SETTING_BRIDGE_PORT_SETTING_NAME,  NM_SETTING_BRIDGE_PORT_PRIORITY,        "priority",     OPTION_NONE, N_("Bridge port priority [32]"), NULL, NULL, NULL },
	{ NM_SETTING_BRIDGE_PORT_SETTING_NAME,  NM_SETTING_BRIDGE_PORT_PATH_COST,       "path-cost",    OPTION_NONE, N_("Bridge port STP path cost [100]"), NULL, NULL, NULL },
	{ NM_SETTING_BRIDGE_PORT_SETTING_NAME,  NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE,    "hairpin",      OPTION_NONE, N_("Hairpin [no]"), NULL,
                                                                                                        set_yes_no, gen_func_bool_values_l10n },
	{ NM_SETTING_VPN_SETTING_NAME,          NM_SETTING_VPN_SERVICE_TYPE,            "vpn-type",     OPTION_REQD, PROMPT_VPN_TYPE, NULL, NULL, gen_func_vpn_types },
	{ NM_SETTING_VPN_SETTING_NAME,          NM_SETTING_VPN_USER_NAME,               "user",         OPTION_NONE, N_("Username [none]"), NULL, NULL, NULL },
	{ NM_SETTING_OLPC_MESH_SETTING_NAME,    NM_SETTING_OLPC_MESH_SSID,              "ssid",         OPTION_REQD, N_("SSID"), NULL, NULL, NULL },
	{ NM_SETTING_OLPC_MESH_SETTING_NAME,    NM_SETTING_OLPC_MESH_CHANNEL,           "channel",      OPTION_NONE, N_("OLPC Mesh channel [1]"), NULL, NULL, NULL },
	{ NM_SETTING_OLPC_MESH_SETTING_NAME,    NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS, "dhcp-anycast", OPTION_NONE, N_("DHCP anycast MAC address [none]"), NULL, NULL, NULL },
	{ NM_SETTING_ADSL_SETTING_NAME,         NM_SETTING_ADSL_USERNAME,               "username",     OPTION_REQD, N_("Username"), NULL, NULL, NULL },
	{ NM_SETTING_ADSL_SETTING_NAME,         NM_SETTING_ADSL_PROTOCOL,               "protocol",     OPTION_REQD, PROMPT_ADSL_PROTO, PROMPT_ADSL_PROTO_CHOICES,
                                                                                                        NULL, gen_func_adsl_proto },
	{ NM_SETTING_ADSL_SETTING_NAME,         NM_SETTING_ADSL_PASSWORD,               "password",     OPTION_NONE, N_("Password [none]"), NULL, NULL, NULL },
	{ NM_SETTING_ADSL_SETTING_NAME,         NM_SETTING_ADSL_ENCAPSULATION,          "encapsulation", OPTION_NONE, PROMPT_ADSL_ENCAP, PROMPT_ADSL_ENCAP_CHOICES,
                                                                                                        NULL, gen_func_adsl_encap },
	{ NM_SETTING_MACVLAN_SETTING_NAME,      NM_SETTING_MACVLAN_PARENT,              "dev",          OPTION_REQD, N_("MACVLAN parent device or connection UUID"), NULL,
                                                                                                        NULL, nmc_rl_gen_func_ifnames },
	{ NM_SETTING_MACVLAN_SETTING_NAME,      NM_SETTING_MACVLAN_MODE,                "mode",         OPTION_REQD, PROMPT_MACVLAN_MODE, NULL,
                                                                                                        NULL, gen_func_macvlan_mode },
	{ NM_SETTING_MACVLAN_SETTING_NAME,      NM_SETTING_MACVLAN_TAP,                 "tap",          OPTION_NONE, N_("Tap [no]"), NULL,
                                                                                                        set_yes_no, gen_func_bool_values_l10n },
	{ NM_SETTING_VXLAN_SETTING_NAME,        NM_SETTING_VXLAN_ID,                    "id",           OPTION_REQD, N_("VXLAN ID"), NULL, NULL, NULL },
	{ NM_SETTING_VXLAN_SETTING_NAME,        NM_SETTING_VXLAN_REMOTE,                "remote",       OPTION_REQD, N_("Remote"), NULL, NULL, NULL },
	{ NM_SETTING_VXLAN_SETTING_NAME,        NM_SETTING_VXLAN_PARENT,                "dev",          OPTION_NONE, N_("Parent device [none]"), NULL,
                                                                                                        NULL, nmc_rl_gen_func_ifnames },
	{ NM_SETTING_VXLAN_SETTING_NAME,        NM_SETTING_VXLAN_LOCAL,                 "local",        OPTION_NONE, N_("Local address [none]"), NULL, NULL, NULL },
	{ NM_SETTING_VXLAN_SETTING_NAME,        NM_SETTING_VXLAN_SOURCE_PORT_MIN,       "source-port-min", OPTION_NONE, N_("Minimum source port [0]"), NULL, NULL, NULL },
	{ NM_SETTING_VXLAN_SETTING_NAME,        NM_SETTING_VXLAN_SOURCE_PORT_MAX,       "source-port-max", OPTION_NONE, N_("Maximum source port [0]"), NULL, NULL, NULL },
	{ NM_SETTING_VXLAN_SETTING_NAME,        NM_SETTING_VXLAN_DESTINATION_PORT,      "destination-port", OPTION_NONE, N_("Destination port [8472]"), NULL, NULL, NULL },
	{ NM_SETTING_TUN_SETTING_NAME,          NM_SETTING_TUN_MODE,                    "mode",         OPTION_NONE, PROMPT_TUN_MODE, PROMPT_TUN_MODE_CHOICES,
                                                                                                        NULL, gen_func_tun_mode },
	{ NM_SETTING_TUN_SETTING_NAME,          NM_SETTING_TUN_OWNER,                   "owner",        OPTION_NONE, N_("User ID [none]"), NULL, NULL, NULL },
	{ NM_SETTING_TUN_SETTING_NAME,          NM_SETTING_TUN_GROUP,                   "group",        OPTION_NONE, N_("Group ID [none]"), NULL, NULL, NULL },
	{ NM_SETTING_TUN_SETTING_NAME,          NM_SETTING_TUN_PI,                      "pi",           OPTION_NONE, N_("Enable PI [no]"), NULL,
                                                                                                        set_yes_no, gen_func_bool_values_l10n },
	{ NM_SETTING_TUN_SETTING_NAME,          NM_SETTING_TUN_VNET_HDR,                "vnet-hdr",     OPTION_NONE, N_("Enable VNET header [no]"), NULL,
                                                                                                        set_yes_no, gen_func_bool_values_l10n },
	{ NM_SETTING_TUN_SETTING_NAME,          NM_SETTING_TUN_MULTI_QUEUE,             "multi-queue",  OPTION_NONE, N_("Enable multi queue [no]"), NULL,
                                                                                                        set_yes_no, gen_func_bool_values_l10n },
	{ NM_SETTING_IP_TUNNEL_SETTING_NAME,    NM_SETTING_IP_TUNNEL_MODE,              "mode",         OPTION_REQD, PROMPT_IP_TUNNEL_MODE, NULL, NULL, gen_func_ip_tunnel_mode },
	{ NM_SETTING_IP_TUNNEL_SETTING_NAME,    NM_SETTING_IP_TUNNEL_LOCAL,             "local",        OPTION_NONE, N_("Local endpoint [none]"), NULL, NULL, NULL },
	{ NM_SETTING_IP_TUNNEL_SETTING_NAME,    NM_SETTING_IP_TUNNEL_REMOTE,            "remote",       OPTION_REQD, N_("Remote"), NULL, NULL, NULL },
	{ NM_SETTING_IP_TUNNEL_SETTING_NAME,    NM_SETTING_IP_TUNNEL_PARENT,            "dev",          OPTION_NONE, N_("Parent device [none]"), NULL,
                                                                                                        NULL, nmc_rl_gen_func_ifnames },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME,   NM_SETTING_IP_CONFIG_ADDRESSES,         "ip4",          OPTION_MULTI, N_("IPv4 address (IP[/plen]) [none]"), NULL,
	                                                                                                set_ip4_address, NULL },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME,   NM_SETTING_IP_CONFIG_GATEWAY,           "gw4",          OPTION_NONE, N_("IPv4 gateway [none]"), NULL, NULL, NULL },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME,   NM_SETTING_IP_CONFIG_ADDRESSES,         "ip6",          OPTION_MULTI, N_("IPv6 address (IP[/plen]) [none]"), NULL,
	                                                                                                set_ip6_address, NULL },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME,   NM_SETTING_IP_CONFIG_GATEWAY,           "gw6",          OPTION_NONE, N_("IPv6 gateway [none]"), NULL, NULL, NULL },
	{ NM_SETTING_PROXY_SETTING_NAME,        NM_SETTING_PROXY_METHOD,                "method",       OPTION_NONE, N_("Proxy method"), NULL, NULL, NULL },
	{ NM_SETTING_PROXY_SETTING_NAME,        NM_SETTING_PROXY_BROWSER_ONLY,          "browser-only", OPTION_NONE, N_("Browser Only"), NULL, NULL, NULL },
	{ NM_SETTING_PROXY_SETTING_NAME,        NM_SETTING_PROXY_PAC_URL,               "pac-url",      OPTION_NONE, N_("PAC Url"), NULL, NULL, NULL },
	{ NM_SETTING_PROXY_SETTING_NAME,        NM_SETTING_PROXY_PAC_SCRIPT,            "pac-script",   OPTION_NONE, N_("PAC Script"), NULL, NULL, NULL },
	{ NULL, NULL, NULL, OPTION_NONE, NULL, NULL, NULL, NULL },
};

static gboolean
option_relevant (NMConnection *connection, OptionInfo *option)
{
	if (option->flags & OPTION_DONT_ASK && !(option->flags & OPTION_ENABLED))
		return FALSE;
	if (option->flags & OPTION_DISABLED)
		return FALSE;
	if (!nm_connection_get_setting_by_name (connection, option->setting_name))
		return FALSE;
	return TRUE;
}

/*----------------------------------------------------------------------------*/

static void
complete_property_name (NmCli *nmc, NMConnection *connection,
			 char modifier,
			 const gchar *prefix,
			 const gchar *postfix)
{
	NMSettingConnection *s_con;
	const NameItem *valid_settings_main = NULL;
	const NameItem *valid_settings_slave = NULL;
	const char *connection_type = NULL;
	const char *slave_type = NULL;
	gs_free char *slv_type = NULL;
	gs_free char *word_list = NULL;
	OptionInfo *candidate;

	connection_type = nm_connection_get_connection_type (connection);
	s_con = nm_connection_get_setting_connection (connection);
	if (s_con)
		slave_type = nm_setting_connection_get_slave_type (s_con);
	slv_type = g_strdup_printf ("%s-slave", slave_type ? slave_type : "no");
	valid_settings_main = get_valid_settings_array (connection_type);
	valid_settings_slave = get_valid_settings_array (slv_type);

	word_list = get_valid_properties_string (valid_settings_main, valid_settings_slave, modifier, prefix, postfix);
	if (word_list)
		g_print ("%s", word_list);

	if (modifier != '\0')
		return;

	for (candidate = option_info; candidate->setting_name; candidate++) {
		if (!nm_connection_get_setting_by_name (connection, candidate->setting_name))
			continue;
		if (!candidate->option)
			continue;
		if (!g_str_has_prefix (candidate->option, prefix))
			continue;
		g_print ("%s\n", candidate->option);
	}
}

static void
run_rl_generator (rl_compentry_func_t *generator_func, const char *prefix)
{
	int state = 0;
	char *str;

	while ((str = generator_func (prefix, state))) {
		g_print ("%s\n", str);
		g_free (str);
		if (state == 0)
			state = 1;
	}
}

static void
complete_option (OptionInfo *option, const gchar *prefix)
{
	if (option->generator_func)
		run_rl_generator (option->generator_func, prefix);
}

static void
complete_property (const gchar *setting_name, const gchar *property, const gchar *prefix)
{
	if (strcmp (setting_name, NM_SETTING_CONNECTION_SETTING_NAME) == 0) {
		if (strcmp (property, NM_SETTING_CONNECTION_TYPE) == 0)
			run_rl_generator (gen_connection_types, prefix);
		else if (strcmp (property, NM_SETTING_CONNECTION_MASTER) == 0)
			run_rl_generator (gen_func_master_ifnames, prefix);
		else if (strcmp (property, NM_SETTING_CONNECTION_INTERFACE_NAME) == 0)
			run_rl_generator (nmc_rl_gen_func_ifnames, prefix);
	} else if (   strcmp (setting_name, NM_SETTING_VPN_SETTING_NAME) == 0
	           && strcmp (property, NM_SETTING_VPN_SERVICE_TYPE) == 0)
		run_rl_generator (gen_func_vpn_types, prefix);
	else if (   strcmp (setting_name, NM_SETTING_WIRELESS_SETTING_NAME) == 0
	         && strcmp (property, NM_SETTING_WIRELESS_MODE) == 0)
		run_rl_generator (gen_func_wifi_mode, prefix);
	else if (   strcmp (setting_name, NM_SETTING_INFINIBAND_SETTING_NAME) == 0
	         && strcmp (property, NM_SETTING_INFINIBAND_TRANSPORT_MODE) == 0)
		run_rl_generator (gen_func_ib_type, prefix);
	else if (   strcmp (setting_name, NM_SETTING_BLUETOOTH_SETTING_NAME) == 0
	         && strcmp (property, NM_SETTING_BLUETOOTH_TYPE) == 0)
		run_rl_generator (gen_func_bt_type, prefix);
	else if (strcmp (setting_name, NM_SETTING_ADSL_SETTING_NAME) == 0) {
		if (strcmp (property, NM_SETTING_ADSL_PROTOCOL) == 0)
			run_rl_generator (gen_func_adsl_proto, prefix);
		else if (strcmp (property, NM_SETTING_ADSL_ENCAPSULATION) == 0)
			run_rl_generator (gen_func_adsl_encap, prefix);
	} else if (   strcmp (setting_name, NM_SETTING_TUN_SETTING_NAME) == 0
	           && strcmp (property, NM_SETTING_TUN_MODE) == 0)
		run_rl_generator (gen_func_tun_mode, prefix);
	else if (strcmp (setting_name, NM_SETTING_IP_TUNNEL_SETTING_NAME) == 0) {
		if (strcmp (property, NM_SETTING_IP_TUNNEL_MODE) == 0)
			run_rl_generator (gen_func_ip_tunnel_mode, prefix);
		else if (strcmp (property, NM_SETTING_IP_TUNNEL_PARENT) == 0)
			run_rl_generator (nmc_rl_gen_func_ifnames, prefix);
	} else if (strcmp (setting_name, NM_SETTING_MACVLAN_SETTING_NAME) == 0) {
		if (strcmp (property, NM_SETTING_MACVLAN_MODE) == 0)
			run_rl_generator (gen_func_macvlan_mode, prefix);
		else if (strcmp (property, NM_SETTING_MACVLAN_PARENT) == 0)
			run_rl_generator (nmc_rl_gen_func_ifnames, prefix);
		else if (strcmp (property, NM_SETTING_MACVLAN_TAP) == 0)
			run_rl_generator (gen_func_bool_values_l10n, prefix);
	} else if (   strcmp (setting_name, NM_SETTING_VXLAN_SETTING_NAME) == 0
	           && strcmp (property, NM_SETTING_VXLAN_PARENT) == 0)
		run_rl_generator (nmc_rl_gen_func_ifnames, prefix);

}

/*----------------------------------------------------------------------------*/

static gboolean
get_value (const char **value, int *argc, char ***argv, const char *option, GError **error)
{
	if (!**argv) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
		             _("Error: value for '%s' is missing."), option);
		return FALSE;
	}

	/* Empty string will reset the value to default */
	if (**argv[0] == '\0')
		*value = NULL;
	else
		*value = *argv[0];

	next_arg (argc, argv);
	return TRUE;
}

gboolean
nmc_read_connection_properties (NmCli *nmc,
                                NMConnection *connection,
                                int *argc,
                                char ***argv,
                                GError **error)
{
	const char *option;
	const char *value = NULL;
	GError *local = NULL;

	/* First check if we have a slave-type, as this would mean we will not
	 * have ip properties but possibly others, slave-type specific.
	 */
	/* Go through arguments and set properties */
	do {
		OptionInfo *candidate;
		OptionInfo *chosen = NULL;
		gs_strfreev gchar **strv = NULL;
		const NameItem *type_settings, *slv_settings;
		char modifier = '\0';

		if (!con_settings (connection, &type_settings, &slv_settings, error))
			return FALSE;

		ensure_settings (connection, slv_settings);
		ensure_settings (connection, type_settings);

		option = **argv;
		if (!option) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("Error: <setting>.<property> argument is missing."));
			return FALSE;
		}

		if (option[0] == '+' || option[0] == '-')
			modifier = *option;

		strv = g_strsplit (option, ".", 2);
		if (g_strv_length (strv) == 2) {
			/* This seems like a <setting>.<property> (such as "connection.id" or "bond.mode"),
			 * optionally prefixed with "+| or "-". */
			char *setting = strv[0];
			const char *setting_name;

			if (modifier)
				setting++;

			if (*argc == 1 && nmc->complete)
				complete_property_name (nmc, connection, modifier, setting, strv[1]);

			setting_name = check_valid_name (setting, type_settings, slv_settings, &local);
			if (!setting_name) {
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
				             _("Error: invalid or not allowed setting '%s': %s."),
				             setting, local->message);
				g_clear_error (&local);
				return FALSE;
			}

			next_arg (argc, argv);
			if (!get_value (&value, argc, argv, option, error))
				return FALSE;

			if (!*argc && nmc->complete)
				complete_property (setting, strv[1], value ? value : "");

			if (!set_property (connection, setting_name, strv[1], value, modifier, error))
				return FALSE;
		} else {
			/* Let's see if this is an property alias (such as "id", "mode", "type" or "con-name")*/
			for (candidate = option_info; candidate->setting_name; candidate++) {
				if (g_strcmp0 (candidate->option, option))
					continue;
				if (!check_valid_name (candidate->setting_name, type_settings, slv_settings, NULL))
					continue;
				if (chosen) {
					g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
						     _("Error: '%s' is ambiguous (%s.%s or %s.%s)."), option,
						     chosen->setting_name, chosen->property,
						     candidate->setting_name, candidate->property);
					return FALSE;
				}
				chosen = candidate;
			}

			if (!chosen) {
				if (modifier)
					option++;
				if (*argc == 1 && nmc->complete)
					complete_property_name (nmc, connection, modifier, option, NULL);
				g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
					     _("Error: invalid <setting>.<property> '%s'."), option);
				return FALSE;
			}

			if (*argc == 1 && nmc->complete)
				complete_property_name (nmc, connection, modifier, option, NULL);

			next_arg (argc, argv);
			if (!get_value (&value, argc, argv, option, error))
				return FALSE;

			if (!*argc && nmc->complete)
				complete_option (chosen, value ? value : "");

			if (!set_option (nmc, connection, chosen, value, error))
				return FALSE;
		}

	} while (*argc);

	return TRUE;
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
	gs_free char *no = g_strdup_printf ("[%s]: ", gettext ("no"));
	gs_free char *yes = g_strdup_printf ("[%s]: ", gettext ("yes"));

	/* Disable readline's default filename completion */
	rl_attempted_completion_over = 1;

	/* Restore standard append character to space */
	rl_completion_append_character = '\x00';

	if (!is_single_word (rl_line_buffer))
		return NULL;

	if (g_str_has_prefix (rl_prompt, PROMPT_CON_TYPE))
		generator_func = gen_connection_types;
	else if (g_str_has_prefix (rl_prompt, PROMPT_IFNAME))
		generator_func = nmc_rl_gen_func_ifnames;
	else if (g_str_has_prefix (rl_prompt, PROMPT_VPN_TYPE))
		generator_func = gen_func_vpn_types;
	else if (g_str_has_prefix (rl_prompt, PROMPT_MASTER))
		generator_func = gen_func_master_ifnames;
	else if (g_str_has_prefix (rl_prompt, PROMPT_WIFI_MODE))
		generator_func = gen_func_wifi_mode;
	else if (g_str_has_prefix (rl_prompt, PROMPT_IB_MODE))
		generator_func = gen_func_ib_type;
	else if (g_str_has_prefix (rl_prompt, PROMPT_BT_TYPE))
		generator_func = gen_func_bt_type;
	else if (g_str_has_prefix (rl_prompt, PROMPT_BOND_MODE))
		generator_func = gen_func_bond_mode;
	else if (g_str_has_prefix (rl_prompt, PROMPT_BOND_MON_MODE))
		generator_func = gen_func_bond_mon_mode;
	else if (g_str_has_prefix (rl_prompt, PROMPT_ADSL_PROTO))
		generator_func = gen_func_adsl_proto;
	else if (g_str_has_prefix (rl_prompt, PROMPT_ADSL_ENCAP))
		generator_func = gen_func_adsl_encap;
	else if (g_str_has_prefix (rl_prompt, PROMPT_TUN_MODE))
		generator_func = gen_func_tun_mode;
	else if (g_str_has_prefix (rl_prompt, PROMPT_IP_TUNNEL_MODE))
		generator_func = gen_func_ip_tunnel_mode;
	else if (g_str_has_prefix (rl_prompt, PROMPT_MACVLAN_MODE))
		generator_func = gen_func_macvlan_mode;
	else if (   g_str_has_suffix (rl_prompt, yes)
	         || g_str_has_suffix (rl_prompt, no))
		generator_func = gen_func_bool_values_l10n;

	if (generator_func)
		match_array = rl_completion_matches (text, generator_func);

	return match_array;
}

static void
ask_option (NmCli *nmc, NMConnection *connection, OptionInfo *option)
{
	gchar *value;
	GError *error = NULL;
	gs_free gchar *prompt = NULL;
	gboolean multi = option->flags & OPTION_MULTI;

	prompt = g_strjoin ("",
	                    gettext (option->prompt),
	                    option->def_hint ? " " : "",
	                    option->def_hint ? option->def_hint : "",
	                    ": ",
	                    NULL);

	if (multi)
		g_print (_("You can specify this option more than once. Press <Enter> when you're done.\n"));

again:
	value = nmc_readline ("%s", prompt);
	if (multi && !value)
		return;

	if (!set_option (nmc, connection, option, value, &error)) {
		g_printerr ("%s\n", error->message);
		g_clear_error (&error);
		goto again;
	}

	if (multi && value)
		goto again;
}

static void
questionnaire_mandatory (NmCli *nmc, NMConnection *connection)
{
	OptionInfo *candidate;

	/* Mandatory settings. */
	for (candidate = option_info; candidate->setting_name; candidate++) {
		if (!option_relevant (connection, candidate))
			continue;
		if (candidate->flags & OPTION_REQD || candidate->flags & OPTION_ENABLED)
			ask_option (nmc, connection, candidate);
	}
}

static gboolean
want_provide_opt_args (const char *type, int num)
{
	char *answer;
	gboolean ret = TRUE;

	/* Ask for optional arguments. */
	g_print (ngettext ("There is %d optional setting for %s.\n",
	                   "There are %d optional settings for %s.\n", num),
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

static const char *
setting_name_to_name (const char *name)
{
	if (strcmp (name, NM_SETTING_WIRED_SETTING_NAME) == 0)
		return _("Wired Ethernet");
	if (strcmp (name, NM_SETTING_INFINIBAND_SETTING_NAME) == 0)
		return _("InfiniBand connection");
	if (strcmp (name, NM_SETTING_WIRELESS_SETTING_NAME) == 0)
		return _("Wi-Fi connection");
	if (strcmp (name, NM_SETTING_WIMAX_SETTING_NAME) == 0)
		return _("WiMAX connection");
	if (strcmp (name, NM_SETTING_PPPOE_SETTING_NAME) == 0)
		return _("PPPoE");
	if (strcmp (name, NM_SETTING_CDMA_SETTING_NAME) == 0)
		return _("CDMA mobile broadband connection");
	if (strcmp (name, NM_SETTING_GSM_SETTING_NAME) == 0)
		return _("GSM mobile broadband connection");
	if (strcmp (name, NM_SETTING_BLUETOOTH_SETTING_NAME) == 0)
		return _("bluetooth connection");
	if (strcmp (name, NM_SETTING_VLAN_SETTING_NAME) == 0)
		return _("VLAN connection");
	if (strcmp (name, NM_SETTING_BOND_SETTING_NAME) == 0)
		return _("Bond device");
	if (strcmp (name, NM_SETTING_TEAM_SETTING_NAME) == 0)
		return _("Team device");
	if (strcmp (name, NM_SETTING_TEAM_PORT_SETTING_NAME) == 0)
		return _("Team port");
	if (strcmp (name, NM_SETTING_BRIDGE_SETTING_NAME) == 0)
		return _("Bridge device");
	if (strcmp (name, NM_SETTING_BRIDGE_PORT_SETTING_NAME) == 0)
		return _("Bridge port");
	if (strcmp (name, NM_SETTING_VPN_SETTING_NAME) == 0)
		return _("VPN connection");
	if (strcmp (name, NM_SETTING_OLPC_MESH_SETTING_NAME) == 0)
		return _("OLPC Mesh connection");
	if (strcmp (name, NM_SETTING_ADSL_SETTING_NAME) == 0)
		return _("ADSL connection");
	if (strcmp (name, NM_SETTING_MACVLAN_SETTING_NAME) == 0)
		return _("macvlan connection");
	if (strcmp (name, NM_SETTING_VXLAN_SETTING_NAME) == 0)
		return _("VXLAN connection");
	if (strcmp (name, NM_SETTING_TUN_SETTING_NAME) == 0)
		return _("Tun device");
	if (strcmp (name, NM_SETTING_IP4_CONFIG_SETTING_NAME) == 0)
		return _("IPv4 protocol");
	if (strcmp (name, NM_SETTING_IP6_CONFIG_SETTING_NAME) == 0)
		return _("IPv6 protocol");
	if (strcmp (name, NM_SETTING_PROXY_SETTING_NAME) == 0)
		return _("Proxy");

	/* Should not happen; but let's still try to be somewhat sensible. */
	return name;
}

static gboolean
questionnaire_one_optional (NmCli *nmc, NMConnection *connection)
{
	OptionInfo *candidate;

	/* Optional settings. */
	const gchar *setting_name = NULL;
	int count = 0;

	/* Find first setting with relevant options and count them. */
	for (candidate = option_info; candidate->setting_name; candidate++) {
		if (!option_relevant (connection, candidate))
			continue;
		if (!setting_name)
			setting_name = candidate->setting_name;
		else if (strcmp (setting_name, candidate->setting_name))
			break;
		count++;
	}
	if (!setting_name)
		return FALSE;

	/* Now ask for the settings. */
	if (want_provide_opt_args (setting_name_to_name (setting_name), count)) {
		for (candidate = option_info; candidate->setting_name; candidate++) {
			if (!option_relevant (connection, candidate))
				continue;
			if (strcmp (setting_name, candidate->setting_name))
				continue;
			ask_option (nmc, connection, candidate);
		}
	}

	/* Make sure we won't ask again. */
	disable_options (setting_name, NULL);

	return TRUE;
}

static NMCResultCode
do_connection_add (NmCli *nmc, int argc, char **argv)
{
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	GError *error = NULL;
	AddConnectionInfo *info = NULL;
	gboolean save_bool = TRUE;
	OptionInfo *candidate;
	gboolean seen_dash_dash = FALSE;

	rl_attempted_completion_function = (rl_completion_func_t *) nmcli_con_add_tab_completion;

	nmc->return_value = NMC_RESULT_SUCCESS;

	/* Create a new connection object */
	connection = nm_simple_connection_new ();

	/* Build up the 'connection' setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

read_properties:
	/* Get the arguments from the command line if any */
	if (argc && !nmc_read_connection_properties (nmc, connection, &argc, &argv, &error)) {
		if (g_strcmp0 (*argv, "--") == 0 && !seen_dash_dash) {
			/* This is for compatibility with older nmcli that required
			 * options and properties to be separated with "--" */
			g_clear_error (&error);
			seen_dash_dash = TRUE;
			next_arg (&argc, &argv);
			goto read_properties;
		} else if (g_strcmp0 (*argv, "save") == 0) {
			/* It would be better if "save" was a separate argument and not
			 * mixed with properties, but there's not much we can do about it now. */
			g_clear_error (&error);
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text,
				                 _("Error: value for '%s' argument is required."),
				                "save");
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
			if (!nmc_string_to_bool (*argv, &save_bool, &error)) {
				g_string_printf (nmc->return_text, _("Error: 'save': %s."),
				                 error->message);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				g_clear_error (&error);
				goto finish;
			}
			next_arg (&argc, &argv);
			goto read_properties;
		}

		g_string_assign (nmc->return_text, error->message);
		nmc->return_value = error->code;
		g_clear_error (&error);
		goto finish;
	}

	if (nmc->complete)
		goto finish;

	/* Now ask user for the rest of the mandatory options. */
	if (nmc->ask)
		questionnaire_mandatory (nmc, connection);

	/* Traditionally, we didn't ask for these options for ethernet slaves. They don't
	 * make much sense, since these are likely to be set by the master anyway. */
	if (nm_setting_connection_get_slave_type (s_con)) {
		disable_options (NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_MTU);
		disable_options (NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_MAC_ADDRESS);
		disable_options (NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_CLONED_MAC_ADDRESS);
	}

	/* Connection id is special in that it's required but we don't insist
	 * on getting it from the user -- we just make up something sensible. */
	if (!nm_setting_connection_get_id (s_con)) {
		const char *ifname = nm_setting_connection_get_interface_name (s_con);
		const char *type = nm_setting_connection_get_connection_type (s_con);
		const char *slave_type = nm_setting_connection_get_slave_type (s_con);
		char *try_name, *default_name;

		/* If only bother when there's a type, which is not guaranteed at this point.
		 * Otherwise the validation will fail anyway. */
		if (type) {
			try_name = ifname ? g_strdup_printf ("%s-%s", get_name_alias (type, slave_type, nmc_valid_connection_types), ifname)
					  : g_strdup (get_name_alias (type, slave_type, nmc_valid_connection_types));
			default_name = nmc_unique_connection_name (nmc->connections, try_name);
			g_free (try_name);
			g_object_set (s_con, NM_SETTING_CONNECTION_ID, default_name, NULL);
			g_free (default_name);
		}
	}

	/* For some software connection types we generate the interface name for the user. */
	set_default_interface_name (nmc, s_con);

	/* Now see if there's something optional that needs to be asked for.
	 * Keep asking until there's no more things to ask for. */
	do {
		/* This ensures all settings that make sense are present. */
		nm_connection_normalize (connection, NULL, NULL, NULL);
	} while (nmc->ask && questionnaire_one_optional (nmc, connection));

	/* Mandatory settings. No good reason to check this other than guarding the user
	 * from doing something that's not likely to make sense (such as missing ifname
	 * on a bond/bridge/team, etc.). Added just to preserve traditional behavior, it
	 * perhaps is a good idea to just remove this. */
	for (candidate = option_info; candidate->setting_name; candidate++) {
		if (!option_relevant (connection, candidate))
			continue;
		if (candidate->flags & OPTION_REQD) {
			g_string_printf (nmc->return_text, _("Error: '%s' argument is required."), candidate->option);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto finish;
		}
	}

	nmc->should_wait++;

	info = g_malloc0 (sizeof (AddConnectionInfo));
	info->nmc = nmc;
	info->con_name = g_strdup (nm_connection_get_id (connection));

	/* Tell the settings service to add the new connection */
	add_new_connection (save_bool,
	                    nmc->client,
	                    connection,
	                    add_connection_cb,
	                    info);

finish:
	reset_options ();
	if (connection)
		g_object_unref (connection);

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
		con = nmc_find_connection (nmc_tab_completion.nmc->connections, "uuid", array[i], NULL, FALSE);
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
	const char *words[] = { "normal", "black", "red", "green", "yellow",
	                        "blue", "magenta", "cyan", "white", NULL };
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
	static int list_idx, len, is_slv;
	const char *s_name, *a_name;
	const NameItem *valid_settings_arr;
	NMSettingConnection *s_con;
	const char *s_type = NULL;
	char *slv_type;

	if (!state) {
		list_idx = 0;
		len = strlen (text);
		is_slv = 0;
	}

	if (!is_slv) {
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

		/* Let's give a try to parameters related to slave type */
		list_idx = 0;
		is_slv = 1;
	}

	/* is_slv */
	s_con = nm_connection_get_setting_connection (nmc_tab_completion.connection);
	if (s_con)
		s_type = nm_setting_connection_get_slave_type (s_con);
	slv_type = g_strdup_printf ("%s-slave", s_type ? s_type : "no");
	valid_settings_arr = get_valid_settings_array (slv_type);
	g_free (slv_type);

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
	const NameItem *valid_settings_main;
	const NameItem *valid_settings_slave;
	const char *p1;
	const char *slv_type;

	/* Try to get the setting from 'line' - setting_name.property */
	p1 = strchr (line, '.');
	if (p1) {
		while (p1 > line && !g_ascii_isspace (*p1))
			p1--;

		strv = g_strsplit (p1+1, ".", 2);

		valid_settings_main = get_valid_settings_array (nmc_tab_completion.con_type);

		/* Support autocompletion of slave-connection parameters
		 * guessing the slave type from the setting name already
		 * typed (or autocompleted) */
		if (nm_streq0 (strv[0], NM_SETTING_TEAM_PORT_SETTING_NAME))
			slv_type = "team-slave";
		else if (nm_streq0 (strv[0], NM_SETTING_BRIDGE_PORT_SETTING_NAME))
			slv_type = "bridge-slave";
		else
			slv_type = "no-slave";
		valid_settings_slave = get_valid_settings_array (slv_type);

		setting_name = check_valid_name (strv[0],
		                                 valid_settings_main,
		                                 valid_settings_slave,
		                                 NULL);
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

static const char **
_create_vpn_array (const GPtrArray *connections, gboolean uuid)
{
	int c, idx = 0;
	const char **array;

	if (connections->len < 1)
		return NULL;

	array = g_new (const char *, connections->len + 1);
	for (c = 0; c < connections->len; c++) {
		NMConnection *connection = NM_CONNECTION (connections->pdata[c]);
		const char *type = nm_connection_get_connection_type (connection);

		if (g_strcmp0 (type, NM_SETTING_VPN_SETTING_NAME) == 0)
			array[idx++] = uuid ? nm_connection_get_uuid (connection) : nm_connection_get_id (connection);
	}
	array[idx] = NULL;
	return array;
}

static char *
gen_vpn_uuids (const char *text, int state)
{
	const GPtrArray *connections = nm_cli.connections;
	const char **uuids;
	char *ret;

	if (connections->len < 1)
		return NULL;

	uuids = _create_vpn_array (connections, TRUE);
	ret = nmc_rl_gen_func_basic (text, state, uuids);
	g_free (uuids);
	return ret;
}

static char *
gen_vpn_ids (const char *text, int state)
{
	const GPtrArray *connections = nm_cli.connections;
	const char **ids;
	char *ret;

	if (connections->len < 1)
		return NULL;

	ids = _create_vpn_array (connections, FALSE);
	ret = nmc_rl_gen_func_basic (text, state, ids);
	g_free (ids);
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

static void
get_setting_and_property (const char *prompt, const char *line,
                          NMSetting **setting_out, char**property_out)
{
	const NameItem *valid_settings_main;
	const NameItem *valid_settings_slave;
	const char *setting_name;
	NMSetting *setting = NULL;
	char *property = NULL;
	char *sett = NULL, *prop = NULL;
	NMSettingConnection *s_con;
	const char *s_type = NULL;
	char *slv_type;

	extract_setting_and_property (prompt, line, &sett, &prop);
	if (sett) {
		/* Is this too much (and useless?) effort for an unlikely case? */
		s_con = nm_connection_get_setting_connection (nmc_tab_completion.connection);
		if (s_con)
			s_type = nm_setting_connection_get_slave_type (s_con);
		slv_type = g_strdup_printf ("%s-slave", s_type ? s_type : "no");

		valid_settings_main = get_valid_settings_array (nmc_tab_completion.con_type);
		valid_settings_slave = get_valid_settings_array (slv_type);
		g_free (slv_type);

		setting_name = check_valid_name (sett, valid_settings_main,
		                                 valid_settings_slave,  NULL);
		setting = nmc_setting_new_for_name (setting_name);
	} else
		setting = nmc_tab_completion.setting ? g_object_ref (nmc_tab_completion.setting) : NULL;

	if (setting && prop)
		property = is_property_valid (setting, prop, NULL);
	else
		property = g_strdup (nmc_tab_completion.property);

	*setting_out = setting;
	*property_out = property;

	g_free (sett);
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

static const char **
get_allowed_property_values (void)
{
	NMSetting *setting;
	char *property;
	const char **avals = NULL;

	get_setting_and_property (rl_prompt, rl_line_buffer, &setting, &property);
	if (setting && property)
		avals = nmc_setting_get_property_allowed_values (setting, property);

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

//FIXME: this helper should go to libnm later
static gboolean
_setting_property_is_boolean (NMSetting *setting, const char *property_name)
{
	GParamSpec *pspec;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (property_name, FALSE);

	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (setting), property_name);
	if (pspec && pspec->value_type == G_TYPE_BOOLEAN)
		return TRUE;
	return FALSE;
}

static gboolean
should_complete_boolean (const char *prompt, const char *line)
{
	NMSetting *setting;
	char *property;
	gboolean is_boolean = FALSE;

	get_setting_and_property (prompt, line, &setting, &property);
	if (setting && property)
		is_boolean = _setting_property_is_boolean (setting, property);

	if (setting)
		g_object_unref (setting);
	g_free (property);

	return is_boolean;
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
						} else if (should_complete_boolean (NULL, line) && num == 3)
							generator_func = gen_func_bool_values;
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
					} else if (should_complete_boolean (prompt_tmp, NULL) && num <= 2)
						generator_func = gen_func_bool_values;
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
		if (g_error_matches (err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE))
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
			if (   !g_error_matches (err, G_FILE_ERROR, G_FILE_ERROR_NOENT)
			    && !g_error_matches (err, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND)) {
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

/*
 * Store 'error' to shared 'nmc_editor_error' and monitoring info to
 * 'nmc_editor_monitor_ac' and signal the condition so that
 * the 'editor-thread' thread could process that.
 */
static void
set_info_and_signal_editor_thread (GError *error, MonitorACInfo *monitor_ac_info)
{
	nmc_editor_cb_called = TRUE;
	nmc_editor_error = error ? g_error_copy (error) : NULL;
	nmc_editor_monitor_ac = monitor_ac_info;
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
	info->monitor_id = 0;
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
			monitor_ac_info = g_malloc0 (sizeof (MonitorACInfo));
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

	prompt = nmc_colorize (nmc, nmc->editor_prompt_color, NMC_TERM_FORMAT_NORMAL,
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
create_setting_by_name (const char *name, const NameItem *valid_settings_main, const NameItem *valid_settings_slave)
{
	const char *setting_name;
	NMSetting *setting = NULL;

	/* Get a valid setting name */
	setting_name = check_valid_name (name, valid_settings_main, valid_settings_slave, NULL);

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
                   const NameItem *valid_settings_main,
                   const NameItem *valid_settings_slave,
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

	if (!(setting_name = check_valid_name (setting_name_user,
	                                       valid_settings_main,
	                                       valid_settings_slave,
	                                       &err))) {
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
menu_switch_to_level0 (NmCli *nmc,
                       NmcEditorMenuContext *menu_ctx,
                       const char *prompt,
                       NmcTermColor prompt_color)
{
	menu_ctx->level = 0;
	g_free (menu_ctx->main_prompt);
	menu_ctx->main_prompt = nmc_colorize (nmc, prompt_color, NMC_TERM_FORMAT_NORMAL, "%s", prompt);
	menu_ctx->curr_setting = NULL;
	g_strfreev (menu_ctx->valid_props);
	menu_ctx->valid_props = NULL;
	g_free (menu_ctx->valid_props_str);
	menu_ctx->valid_props_str = NULL;
}

static void
menu_switch_to_level1 (NmCli *nmc,
                       NmcEditorMenuContext *menu_ctx,
                       NMSetting *setting,
                       const char *setting_name,
                       NmcTermColor prompt_color)
{
	menu_ctx->level = 1;
	g_free (menu_ctx->main_prompt);
	menu_ctx->main_prompt = nmc_colorize (nmc, prompt_color, NMC_TERM_FORMAT_NORMAL,
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
	NMSettingConnection *s_con;
	NMRemoteConnection *rem_con;
	NMRemoteConnection *con_tmp;
	GWeakRef weak = { { NULL } };
	gboolean removed;
	NmcEditorMainCmd cmd;
	char *cmd_user;
	gboolean cmd_loop = TRUE;
	char *cmd_arg = NULL;
	char *cmd_arg_s, *cmd_arg_p, *cmd_arg_v;
	const NameItem *valid_settings_main = NULL;
	const NameItem *valid_settings_slave = NULL;
	char *valid_settings_str = NULL;
	const char *s_type = NULL;
	char *slv_type;
	AddConnectionInfo *info = NULL;
	gboolean dirty;
	gboolean temp_changes;
	GError *err1 = NULL;
	NmcEditorMenuContext menu_ctx;

	s_con = nm_connection_get_setting_connection (connection);
	if (s_con)
		s_type = nm_setting_connection_get_slave_type (s_con);
	slv_type = g_strdup_printf ("%s-slave", s_type ? s_type : "no");

	valid_settings_main = get_valid_settings_array (connection_type);
	valid_settings_slave = get_valid_settings_array (slv_type);
	g_free (slv_type);

	valid_settings_str = get_valid_options_string (valid_settings_main, valid_settings_slave);
	g_print (_("You may edit the following settings: %s\n"), valid_settings_str);

	menu_ctx.level = 0;
	menu_ctx.main_prompt = nmc_colorize (nmc, nmc->editor_prompt_color, NMC_TERM_FORMAT_NORMAL,
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
					ss = is_setting_valid (connection, valid_settings_main, valid_settings_slave, cmd_arg_s);
					if (!ss) {
						ss = create_setting_by_name (cmd_arg_s, valid_settings_main, valid_settings_slave);
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

				setting_name = ask_check_setting (user_arg,
								  valid_settings_main,
								  valid_settings_slave,
								  valid_settings_str);
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

					if (NM_IS_SETTING_WIRELESS (setting))
						nmc_setting_wireless_connect_handlers (NM_SETTING_WIRELESS (setting));
					else if (NM_IS_SETTING_IP4_CONFIG (setting))
						nmc_setting_ip4_connect_handlers (NM_SETTING_IP_CONFIG (setting));
					else if (NM_IS_SETTING_IP6_CONFIG (setting))
						nmc_setting_ip6_connect_handlers (NM_SETTING_IP_CONFIG (setting));
					else if (NM_IS_SETTING_PROXY (setting))
						nmc_setting_proxy_connect_handlers (NM_SETTING_PROXY (setting));

					nm_connection_add_setting (connection, setting);
				}
				/* Set global variable for use in TAB completion */
				nmc_tab_completion.setting = setting;

				/* Switch to level 1 */
				menu_switch_to_level1 (nmc, &menu_ctx, setting, setting_name, nmc->editor_prompt_color);

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
					ss = is_setting_valid (connection,
							       valid_settings_main,
							       valid_settings_slave,
							       user_s);
					if (!ss) {
						if (check_valid_name (user_s,
						                      valid_settings_main,
						                      valid_settings_slave,
						                      NULL))
							g_print (_("Setting '%s' is not present in the connection.\n"),
								 user_s);
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
						menu_switch_to_level0 (nmc, &menu_ctx, BASE_PROMPT, nmc->editor_prompt_color);
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
						s_tmp = is_setting_valid (connection,
									  valid_settings_main,
									  valid_settings_slave,
									  cmd_arg_p);
						if (s_tmp) {
							/* Remove setting from the connection */
							connection_remove_setting (connection, s_tmp);
							/* coverity[copy_paste_error] - suppress Coverity COPY_PASTE_ERROR defect */
							if (ss == menu_ctx.curr_setting) {
								/* If we removed the setting we are in, go up */
								menu_switch_to_level0 (nmc, &menu_ctx, BASE_PROMPT, nmc->editor_prompt_color);
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
					ss = is_setting_valid (connection,
							       valid_settings_main,
							       valid_settings_slave,
							       user_s);
					if (!ss) {
						ss = create_setting_by_name (user_s,
									     valid_settings_main,
									     valid_settings_slave);
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
						s_tmp = is_setting_valid (connection,
									  valid_settings_main,
									  valid_settings_slave,
									  cmd_arg_p);
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
						s_name = check_valid_name (user_s,
						                           valid_settings_main,
						                           valid_settings_slave,
						                           NULL);
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
							s_tmp = is_setting_valid (connection,
										  valid_settings_main,
										  valid_settings_slave,
										  cmd_arg_p);
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

				//FIXME: add also a timeout for cases the callback is not called
				while (!nmc_editor_cb_called)
					g_main_context_iteration (NULL, TRUE);

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
			nmc->should_wait++;
			nmc->print_output = NMC_PRINT_PRETTY;
			if (!nmc_activate_connection (nmc, NM_CONNECTION (rem_con), ifname, ap_nsp, ap_nsp, NULL,
			                              activate_connection_editor_cb, &tmp_err)) {
				g_print (_("Error: Cannot activate connection: %s.\n"), tmp_err->message);
				g_clear_error (&tmp_err);
				break;
			}

			while (!nmc_editor_cb_called)
				g_main_context_iteration (NULL, TRUE);

			if (nmc_editor_error) {
				g_print (_("Error: Failed to activate '%s' (%s) connection: %s\n"),
				         nm_connection_get_id (connection),
				         nm_connection_get_uuid (connection),
				         nmc_editor_error->message);
				g_error_free (nmc_editor_error);
			} else {
				nmc_readline (_("Monitoring connection activation (press any key to continue)\n"));
			}

			if (nmc_editor_monitor_ac) {
				if (nmc_editor_monitor_ac->monitor_id)
					g_source_remove (nmc_editor_monitor_ac->monitor_id);
				g_free (nmc_editor_monitor_ac);
			}
			nmc_editor_cb_called = FALSE;
			nmc_editor_error = NULL;
			nmc_editor_monitor_ac = NULL;

			/* Update timestamp in local connection */
			update_connection_timestamp (NM_CONNECTION (rem_con), connection);

			}
			break;

		case NMC_EDITOR_MAIN_CMD_BACK:
			/* Go back (up) an the menu */
			if (menu_ctx.level == 1) {
				menu_switch_to_level0 (nmc, &menu_ctx, BASE_PROMPT, nmc->editor_prompt_color);
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
						menu_ctx.main_prompt = nmc_colorize (nmc, nmc->editor_prompt_color, NMC_TERM_FORMAT_NORMAL,
						                                     BASE_PROMPT);
					else
						menu_ctx.main_prompt = nmc_colorize (nmc, nmc->editor_prompt_color, NMC_TERM_FORMAT_NORMAL,
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
		nmc_setting_custom_init (base_setting);
		nm_connection_add_setting (connection, base_setting);

		set_default_interface_name (nmc, s_con);

		/* Set sensible initial VLAN values */
		if (g_strcmp0 (con_type, NM_SETTING_VLAN_SETTING_NAME) == 0) {
			const char *dev_ifname = get_ethernet_device_name (nmc);

			g_object_set (NM_SETTING_VLAN (base_setting),
			              NM_SETTING_VLAN_PARENT, dev_ifname ? dev_ifname : "eth0",
			              NULL);
		}


		/* Always add IPv4 and IPv6 settings for non-slave connections */
		setting = nm_setting_ip4_config_new ();
		nmc_setting_custom_init (setting);
		nm_connection_add_setting (connection, setting);

		setting = nm_setting_ip6_config_new ();
		nmc_setting_custom_init (setting);
		nm_connection_add_setting (connection, setting);

		/* Also Proxy Setting */
		setting = nm_setting_proxy_new ();
		nmc_setting_custom_init (setting);
		nm_connection_add_setting (connection, setting);
	}
}

static void
editor_init_existing_connection (NMConnection *connection)
{
	NMSettingIPConfig *s_ip4, *s_ip6;
	NMSettingProxy *s_proxy;
	NMSettingWireless *s_wireless;
	NMSettingConnection *s_con;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	s_proxy = nm_connection_get_setting_proxy (connection);
	s_wireless = nm_connection_get_setting_wireless (connection);
	s_con = nm_connection_get_setting_connection (connection);

	if (s_ip4)
		nmc_setting_ip4_connect_handlers (s_ip4);
	if (s_ip6)
		nmc_setting_ip6_connect_handlers (s_ip6);
	if (s_proxy)
		nmc_setting_proxy_connect_handlers (s_proxy);
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

	/* TODO: complete uuid, path or id */
	if (nmc->complete)
		return nmc->return_value;

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

		found_con = nmc_find_connection (nmc->connections, selector, con, NULL, FALSE);
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
		connection_type = check_valid_name (type, nmc_valid_connection_types, NULL, &err1);
		tmp_str = get_valid_options_string (nmc_valid_connection_types, NULL);

		while (!connection_type) {
			if (!type)
				g_print (_("Valid connection types: %s\n"), tmp_str);
			else
				g_print (_("Error: invalid connection type; %s\n"), err1->message);
			g_clear_error (&err1);

			type_ask = nmc_readline (EDITOR_PROMPT_CON_TYPE);
			type = type_ask = type_ask ? g_strstrip (type_ask) : NULL;
			connection_type = check_valid_name (type_ask, nmc_valid_connection_types, NULL, &err1);
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
			default_name = nmc_unique_connection_name (nmc->connections,
			                                           get_name_alias (connection_type, NULL, nmc_valid_connection_types));

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

	return nmc->return_value;

error:
	g_assert (!connection);
	g_free (type_ask);

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
                      int argc,
                      char **argv)
{
	NMConnection *connection = NULL;
	NMRemoteConnection *rc = NULL;
	GError *error = NULL;
	gboolean temporary = FALSE;

	if (argc && nmc_arg_is_option (*argv, "temporary")) {
		if (nmc->complete)
			goto finish;
		temporary = TRUE;
		next_arg (&argc, &argv);
	}

	connection = get_connection (nmc, &argc, &argv, NULL, &error);
	if (!connection) {
		g_string_printf (nmc->return_text, _("Error: %s."), error->message);
		nmc->return_value = error->code;
		goto finish;
	}

	rc = nm_client_get_connection_by_uuid (nmc->client,
	                                       nm_connection_get_uuid (connection));
	if (!rc) {
		g_string_printf (nmc->return_text, _("Error: Unknown connection '%s'."),
		                 nm_connection_get_uuid (connection));
		nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
		goto finish;
	}

	if (!nmc_read_connection_properties (nmc, NM_CONNECTION (rc), &argc, &argv, &error)) {
		g_string_assign (nmc->return_text, error->message);
		nmc->return_value = error->code;
		g_clear_error (&error);
		goto finish;
	}

	if (nmc->complete)
		goto finish;

	update_connection (!temporary, rc, modify_connection_cb, nmc);
	nmc->should_wait++;

finish:
	return nmc->return_value;
}

typedef struct {
	NmCli *nmc;
	char *orig_id;
	char *orig_uuid;
	char *con_id;
} CloneConnectionInfo;

static void
clone_connection_cb (GObject *client,
                     GAsyncResult *result,
                     gpointer user_data)
{
	CloneConnectionInfo *info = (CloneConnectionInfo *) user_data;
	NmCli *nmc = info->nmc;
	NMRemoteConnection *connection;
	GError *error = NULL;

	connection = nm_client_add_connection_finish (NM_CLIENT (client), result, &error);
	if (error) {
		g_string_printf (nmc->return_text,
		                 _("Error: Failed to add '%s' connection: %s"),
		                 info->con_id, error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
	} else {
		g_print (_("%s (%s) cloned as %s (%s).\n"),
		         info->orig_id,
		         info->orig_uuid,
		         nm_connection_get_id (NM_CONNECTION (connection)),
		         nm_connection_get_uuid (NM_CONNECTION (connection)));
		g_object_unref (connection);
	}

	g_free (info->con_id);
	g_free (info->orig_id);
	g_free (info->orig_uuid);
	g_slice_free (CloneConnectionInfo, info);
	quit ();
}

static NMCResultCode
do_connection_clone (NmCli *nmc, int argc, char **argv)
{
	NMConnection *connection = NULL;
	NMConnection *new_connection = NULL;
	NMSettingConnection *s_con;
	CloneConnectionInfo *info;
	const char *new_name;
	char *new_name_ask = NULL;
	char *uuid;
	gboolean temporary = FALSE;
	char **arg_arr = NULL;
	int arg_num;
	char ***argv_ptr = &argv;
	int *argc_ptr = &argc;
	GError *error = NULL;

	if (argc == 1 && nmc->complete)
		nmc_complete_strings (*argv, "temporary", NULL);

	if (argc == 0 && nmc->ask) {
		char *line;

		/* nmc_do_cmd() should not call this with argc=0. */
		g_assert (!nmc->complete);

		line = nmc_readline ("%s: ", PROMPT_CONNECTION);
		nmc_string_to_arg_array (line, NULL, TRUE, &arg_arr, &arg_num);
		g_free (line);
		argv_ptr = &arg_arr;
		argc_ptr = &arg_num;
	} else if (nmc_arg_is_option (*argv, "temporary")) {
		temporary = TRUE;
		next_arg (&argc, &argv);
	}

	connection = get_connection (nmc, argc_ptr, argv_ptr, NULL, &error);
	if (!connection) {
		g_string_printf (nmc->return_text, _("Error: %s."), error->message);
		nmc->return_value = error->code;
		goto finish;
	}

	if (nmc->complete)
		goto finish;

	if (argv[0])
		new_name = *argv;
	else if (nmc->ask)
		new_name = new_name_ask = nmc_readline (_("New connection name: "));
	else {
		g_string_printf (nmc->return_text, _("Error: <new name> argument is missing."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}

	if (next_arg (argc_ptr, argv_ptr) == 0) {
		g_string_printf (nmc->return_text, _("Error: unknown extra argument: '%s'."), *argv);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}

	/* Copy the connection */
	new_connection = nm_simple_connection_new_clone (connection);

	s_con = nm_connection_get_setting_connection (new_connection);
	g_assert (s_con);
	uuid = nm_utils_uuid_generate ();
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, new_name,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NULL);
	g_free (uuid);

	/* Merge secrets into the new connection */
	update_secrets_in_connection (NM_REMOTE_CONNECTION (connection), new_connection);

	info = g_slice_new0 (CloneConnectionInfo);
	info->nmc = nmc;
	info->orig_id = g_strdup (nm_connection_get_id (connection));
	info->orig_uuid = g_strdup (nm_connection_get_uuid (connection));
	info->con_id = g_strdup (nm_connection_get_id (new_connection));

	/* Add the new cloned connection to NetworkManager */
	add_new_connection (!temporary,
	                    nmc->client,
	                    new_connection,
	                    clone_connection_cb,
	                    info);

	nmc->should_wait++;
finish:
	if (new_connection)
		g_object_unref (new_connection);
	g_free (new_name_ask);

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
	char **arg_arr = NULL, *old_arg;
	char **arg_ptr = argv;
	int arg_num = argc;
	GString *invalid_cons = NULL;
	int pos = 0;
	GError *error = NULL;

	if (nmc->timeout == -1)
		nmc->timeout = 10;

	if (argc == 0) {
		if (nmc->ask) {
			char *line;

			/* nmc_do_cmd() should not call this with argc=0. */
			g_assert (!nmc->complete);

			line = nmc_readline ("%s: ", PROMPT_CONNECTIONS);
			nmc_string_to_arg_array (line, NULL, TRUE, &arg_arr, &arg_num);
			g_free (line);
			arg_ptr = arg_arr;
		}
		if (arg_num == 0) {
			g_string_printf (nmc->return_text, _("Error: No connection specified."));
			nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
			goto finish;
		}
	}

	while (arg_num > 0) {
		old_arg = *arg_ptr;
		connection = get_connection (nmc, &arg_num, &arg_ptr, &pos, &error);
		if (connection) {
			/* Check if the connection is unique. */
			/* Calling delete for the same connection repeatedly would result in
			 * NM responding for the last D-Bus call only and we would stall. */
			if (!g_slist_find (queue, connection))
				queue = g_slist_prepend (queue, g_object_ref (connection));
		} else {
			if (!nmc->complete)
				g_printerr (_("Error: %s.\n"), error->message);
			g_string_printf (nmc->return_text, _("Error: not all connections found."));
			nmc->return_value = error->code;
			g_clear_error (&error);

			if (nmc->return_value != NMC_RESULT_ERROR_NOT_FOUND)
				goto finish;

			if (!invalid_cons)
				invalid_cons = g_string_new (NULL);
			g_string_append_printf (invalid_cons, "'%s', ", old_arg);
		}
	}

	if (!queue) {
		g_string_printf (nmc->return_text, _("Error: No connection specified."));
		nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
		goto finish;
	} else if (nmc->complete) {
		g_slist_free (queue);
		goto finish;
	}
	queue = g_slist_reverse (queue);

	info = g_slice_new0 (ConnectionCbInfo);
	info->nmc = nmc;
	info->queue = queue;
	info->timeout_id = g_timeout_add_seconds (nmc->timeout, connection_op_timeout_cb, info);

	nmc->nowait_flag = (nmc->timeout == 0);
	nmc->should_wait++;

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

static void
connection_changed (NMConnection *connection, NmCli *nmc)
{
	g_print (_("%s: connection profile changed\n"), nm_connection_get_id (connection));
}

static void
connection_watch (NmCli *nmc, NMConnection *connection)
{
	nmc->should_wait++;
	g_signal_connect (connection, NM_CONNECTION_CHANGED, G_CALLBACK (connection_changed), nmc);
}

static void
connection_unwatch (NmCli *nmc, NMConnection *connection)
{
	if (g_signal_handlers_disconnect_by_func (connection, G_CALLBACK (connection_changed), nmc))
		nmc->should_wait--;

	/* Terminate if all the watched connections disappeared. */
	if (!nmc->should_wait)
		quit ();
}

static void
connection_added (NMClient *client, NMRemoteConnection *con, NmCli *nmc)
{
	NMConnection *connection = NM_CONNECTION (con);

	g_print (_("%s: connection profile created\n"), nm_connection_get_id (connection));
	connection_watch (nmc, connection);
}

static void
connection_removed (NMClient *client, NMRemoteConnection *con, NmCli *nmc)
{
	NMConnection *connection = NM_CONNECTION (con);

	g_print (_("%s: connection profile removed\n"), nm_connection_get_id (connection));
	connection_unwatch (nmc, connection);
}

static NMCResultCode
do_connection_monitor (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;

	if (argc == 0) {
		/* No connections specified. Monitor all. */
		int i;

		/* nmc_do_cmd() should not call this with argc=0. */
		g_assert (!nmc->complete);

		nmc->connections = nm_client_get_connections (nmc->client);
		for (i = 0; i < nmc->connections->len; i++)
			connection_watch (nmc, g_ptr_array_index (nmc->connections, i));

		/* We'll watch the connection additions too, never exit. */
		nmc->should_wait++;
		g_signal_connect (nmc->client, NM_CLIENT_CONNECTION_ADDED, G_CALLBACK (connection_added), nmc);
	} else {
		/* Look up the specified connections and watch them. */
		NMConnection *connection;
		int pos = 0;

		do {
			connection = get_connection (nmc, &argc, &argv, &pos, &error);
			if (!connection) {
				if (!nmc->complete)
					g_printerr (_("Error: %s.\n"), error->message);
				g_string_printf (nmc->return_text, _("Error: not all connections found."));
				return error->code;
			}

			if (nmc->complete)
				continue;

			connection_watch (nmc, connection);
		} while (argc > 0);
	}

	if (nmc->complete)
		return nmc->return_value;
	g_signal_connect (nmc->client, NM_CLIENT_CONNECTION_REMOVED, G_CALLBACK (connection_removed), nmc);

	return NMC_RESULT_SUCCESS;
}

static NMCResultCode
do_connection_reload (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;

	if (nmc->complete)
		return nmc->return_value;

	if (!nm_client_reload_connections (nmc->client, NULL, &error)) {
		g_string_printf (nmc->return_text, _("Error: failed to reload connections: %s."),
		                 nmc_error_get_simple_message (error));
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

	if (argc == 0) {
		g_string_printf (nmc->return_text, _("Error: No connection specified."));
		return NMC_RESULT_ERROR_USER_INPUT;
	}

	if (nmc->complete)
		return NMC_RESULT_COMPLETE_FILE;

	filenames = g_new (char *, argc + 1);
	for (i = 0; i < argc; i++)
		filenames[i] = argv[i];
	filenames[i] = NULL;

	nm_client_load_connections (nmc->client, filenames, &failures, NULL, &error);
	g_free (filenames);
	if (error) {
		g_string_printf (nmc->return_text, _("Error: failed to load connection: %s."),
		                 nmc_error_get_simple_message (error));
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

// FIXME: change the text when non-VPN connection types are supported
#define PROMPT_IMPORT_TYPE PROMPT_VPN_TYPE
#define PROMPT_IMPORT_FILE N_("File to import: ")

static NMCResultCode
do_connection_import (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;
	const char *type = NULL, *filename = NULL;
	char *type_ask = NULL, *filename_ask = NULL;
	AddConnectionInfo *info;
	NMConnection *connection = NULL;
	NMVpnEditorPlugin *plugin;
	gs_free char *service_type = NULL;
	gboolean temporary = FALSE;

	if (argc == 0) {
		/* nmc_do_cmd() should not call this with argc=0. */
		g_assert (!nmc->complete);

		if (nmc->ask) {
			type_ask = nmc_readline (gettext (PROMPT_IMPORT_TYPE));
			filename_ask = nmc_readline (gettext (PROMPT_IMPORT_FILE));
			type = type_ask = type_ask ? g_strstrip (type_ask) : NULL;
			filename = filename_ask = filename_ask ? g_strstrip (filename_ask) : NULL;
		} else {
			g_string_printf (nmc->return_text, _("Error: No arguments provided."));
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto finish;
		}
	}

	while (argc > 0) {
		if (argc == 1 && nmc->complete)
			nmc_complete_strings (*argv, "temporary", "type", "file", NULL);
		if (nmc_arg_is_option (*argv, "temporary")) {
			temporary = TRUE;
			next_arg (&argc, &argv);
		}

		if (strcmp (*argv, "type") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
			if (!type)
				type = *argv;
			else
				g_printerr (_("Warning: 'type' already specified, ignoring extra one.\n"));

		} else if (strcmp (*argv, "file") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
			if (argc == 1 && nmc->complete)
				nmc->return_value = NMC_RESULT_COMPLETE_FILE;
			if (!filename)
				filename = *argv;
			else
				g_printerr (_("Warning: 'file' already specified, ignoring extra one.\n"));
		} else {
			g_string_printf (nmc->return_text, _("Unknown parameter: %s"), *argv);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto finish;
		}

		argc--;
		argv++;
	}

	if (nmc->complete)
		goto finish;

	if (!type) {
		g_string_printf (nmc->return_text, _("Error: 'type' argument is required."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}
	if (!filename) {
		g_string_printf (nmc->return_text, _("Error: 'file' argument is required."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}

	service_type = nm_vpn_plugin_info_list_find_service_type (nm_vpn_get_plugin_infos (), type);
	if (!service_type) {
		g_string_printf (nmc->return_text, _("Error: failed to find VPN plugin for %s."), type);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto finish;
	}

	/* Import VPN configuration */
	plugin = nm_vpn_get_editor_plugin (service_type, &error);
	if (!plugin) {
		g_string_printf (nmc->return_text, _("Error: failed to load VPN plugin: %s."),
		                 error->message);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto finish;
	}

	connection = nm_vpn_editor_plugin_import (plugin, filename, &error);
	if (!connection) {
		g_string_printf (nmc->return_text, _("Error: failed to import '%s': %s."),
		                 filename, error->message);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto finish;
	}

	info = g_malloc0 (sizeof (AddConnectionInfo));
	info->nmc = nmc;
	info->con_name = g_strdup (nm_connection_get_id (connection));

	/* Add the new imported connection to NetworkManager */
	add_new_connection (!temporary,
	                    nmc->client,
	                    connection,
	                    add_connection_cb,
	                    info);

	nmc->should_wait++;
finish:
	if (connection)
		g_object_unref (connection);
	g_clear_error (&error);
	g_free (type_ask);
	g_free (filename_ask);
	return nmc->return_value;
}

static NMCResultCode
do_connection_export (NmCli *nmc, int argc, char **argv)
{
	NMConnection *connection = NULL;
	const char *out_name = NULL;
	char *name_ask = NULL;
	char *out_name_ask = NULL;
	const char *path = NULL;
	const char *type = NULL;
	NMVpnEditorPlugin *plugin;
	GError *error = NULL;
	char tmpfile[] = "/tmp/nmcli-export-temp-XXXXXX";
	char **arg_arr = NULL;
	int arg_num;
	char ***argv_ptr = &argv;
	int *argc_ptr = &argc;

	if (argc == 0 && nmc->ask) {
		char *line;

		/* nmc_do_cmd() should not call this with argc=0. */
		g_assert (!nmc->complete);

		line = nmc_readline ("%s: ", PROMPT_VPN_CONNECTION);
		nmc_string_to_arg_array (line, NULL, TRUE, &arg_arr, &arg_num);
		g_free (line);
		argv_ptr = &arg_arr;
		argc_ptr = &arg_num;
	}

	connection = get_connection (nmc, argc_ptr, argv_ptr, NULL, &error);
	if (!connection) {
		g_string_printf (nmc->return_text, _("Error: %s."), error->message);
		nmc->return_value = error->code;
		goto finish;
	}

	if (nmc->complete)
		return nmc->return_value;

	if (next_arg (&argc, &argv) == 0)
		out_name = *argv;
	else if (nmc->ask)
		out_name = out_name_ask = nmc_readline (_("Output file name: "));

	if (next_arg (argc_ptr, argv_ptr) == 0) {
		g_string_printf (nmc->return_text, _("Error: unknown extra argument: '%s'."), *argv);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}

	type = nm_connection_get_connection_type (connection);
	if (g_strcmp0 (type, NM_SETTING_VPN_SETTING_NAME) != 0) {
		g_string_printf (nmc->return_text, _("Error: the connection is not VPN."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}
	type = nm_setting_vpn_get_service_type (nm_connection_get_setting_vpn (connection));

	/* Export VPN configuration */
	plugin = nm_vpn_get_editor_plugin (type, &error);
	if (!plugin) {
		g_string_printf (nmc->return_text, _("Error: failed to load VPN plugin: %s."),
		                 error->message);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto finish;
	}

	if (out_name)
		path = out_name;
	else {
		int fd;
		fd = g_mkstemp (tmpfile);
		if (fd == -1) {
			g_string_printf (nmc->return_text, _("Error: failed to create temporary file %s."), tmpfile);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			goto finish;
		}
		close (fd);
		path = tmpfile;
	}

	if (!nm_vpn_editor_plugin_export (plugin, path, connection, &error)) {
		g_string_printf (nmc->return_text, _("Error: failed to export '%s': %s."),
		                 nm_connection_get_id (connection), error->message);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto finish;
	}

	/* No output file -> copy data to stdout */
	if (!out_name) {
		char *contents = NULL;
		gsize len = 0;
		if (!g_file_get_contents (path, &contents, &len, &error)) {
			g_string_printf (nmc->return_text, _("Error: failed to read temporary file '%s': %s."),
			                 path, error->message);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			goto finish;
		}
		g_print ("%s", contents);
		g_free (contents);
	}

finish:
	if (!out_name && path)
		unlink (path);
	g_clear_error (&error);
	g_free (name_ask);
	g_free (out_name_ask);
	return nmc->return_value;
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
	} else if (g_strcmp0 (rl_prompt, PROMPT_IMPORT_TYPE) == 0) {
		generator_func = gen_func_vpn_types;
	} else if (g_strcmp0 (rl_prompt, PROMPT_IMPORT_FILE) == 0) {
		rl_attempted_completion_over = 0;
		rl_complete_with_tilde_expansion = 1;
	} else if (g_strcmp0 (rl_prompt, PROMPT_VPN_CONNECTION) == 0) {
		generator_func = gen_vpn_ids;
	}

	if (generator_func)
		match_array = rl_completion_matches (text, generator_func);

	return match_array;
}

static const NMCCommand connection_cmds[] = {
	{"show",     do_connections_show,      usage_connection_show },
	{"up",       do_connection_up,         usage_connection_up },
	{"down",     do_connection_down,       usage_connection_down },
	{"add",      do_connection_add,        usage_connection_add },
	{"edit",     do_connection_edit,       usage_connection_edit },
	{"delete",   do_connection_delete,     usage_connection_delete },
	{"reload",   do_connection_reload,     usage_connection_reload },
	{"load",     do_connection_load,       usage_connection_load },
	{"modify",   do_connection_modify,     usage_connection_modify },
	{"clone",    do_connection_clone,      usage_connection_clone },
	{"import",   do_connection_import,     usage_connection_import },
	{"export",   do_connection_export,     usage_connection_export },
	{"monitor",  do_connection_monitor,    usage_connection_monitor },
	{NULL,       do_connections_show,      usage },
};

/* Entry point function for connections-related commands: 'nmcli connection' */
NMCResultCode
do_connections (NmCli *nmc, int argc, char **argv)
{
	/* Register polkit agent */
	nmc_start_polkit_agent_start_try (nmc);

	/* Set completion function for 'nmcli con' */
	rl_attempted_completion_function = (rl_completion_func_t *) nmcli_con_tab_completion;

	/* Get NMClient object early */
	nmc->get_client (nmc);

	/* Check whether NetworkManager is running */
	if (!nm_client_get_nm_running (nmc->client)) {
		if (!nmc->complete) {
			g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
			nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		}
		return nmc->return_value;
	}

	/* Get the connection list */
	nmc->connections = nm_client_get_connections (nmc->client);

	return nmc_do_cmd (nmc, connection_cmds, *argv, argc, argv);
}

void
monitor_connections (NmCli *nmc)
{
	do_connection_monitor (nmc, 0, NULL);
}
