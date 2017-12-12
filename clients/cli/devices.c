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
 * Copyright 2010 - 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include "devices.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <readline/readline.h>

#include "nm-secret-agent-simple.h"
#include "nm-client-utils.h"

#include "polkit-agent.h"
#include "utils.h"
#include "common.h"
#include "connections.h"

/* define some prompts */
#define PROMPT_INTERFACE  _("Interface: ")
#define PROMPT_INTERFACES _("Interface(s): ")

const NmcMetaGenericInfo *const nmc_fields_dev_status[] = {
	NMC_META_GENERIC ("DEVICE"),       /* 0 */
	NMC_META_GENERIC ("TYPE"),         /* 1 */
	NMC_META_GENERIC ("STATE"),        /* 2 */
	NMC_META_GENERIC ("DBUS-PATH"),    /* 3 */
	NMC_META_GENERIC ("CONNECTION"),   /* 4 */
	NMC_META_GENERIC ("CON-UUID"),     /* 5 */
	NMC_META_GENERIC ("CON-PATH"),     /* 6 */
	NULL,
};
#define NMC_FIELDS_DEV_STATUS_COMMON  "DEVICE,TYPE,STATE,CONNECTION"


const NmcMetaGenericInfo *const nmc_fields_dev_show_general[] = {
	NMC_META_GENERIC ("NAME"),                /* 0 */
	NMC_META_GENERIC ("DEVICE"),              /* 1 */
	NMC_META_GENERIC ("TYPE"),                /* 2 */
	NMC_META_GENERIC ("NM-TYPE"),             /* 3 */
	NMC_META_GENERIC ("VENDOR"),              /* 4 */
	NMC_META_GENERIC ("PRODUCT"),             /* 5 */
	NMC_META_GENERIC ("DRIVER"),              /* 6 */
	NMC_META_GENERIC ("DRIVER-VERSION"),      /* 7 */
	NMC_META_GENERIC ("FIRMWARE-VERSION"),    /* 8 */
	NMC_META_GENERIC ("HWADDR"),              /* 9 */
	NMC_META_GENERIC ("MTU"),                 /* 10 */
	NMC_META_GENERIC ("STATE"),               /* 11 */
	NMC_META_GENERIC ("REASON"),              /* 12 */
	NMC_META_GENERIC ("UDI"),                 /* 13 */
	NMC_META_GENERIC ("IP-IFACE"),            /* 14 */
	NMC_META_GENERIC ("IS-SOFTWARE"),         /* 15 */
	NMC_META_GENERIC ("NM-MANAGED"),          /* 16 */
	NMC_META_GENERIC ("AUTOCONNECT"),         /* 17 */
	NMC_META_GENERIC ("FIRMWARE-MISSING"),    /* 18 */
	NMC_META_GENERIC ("NM-PLUGIN-MISSING"),   /* 19 */
	NMC_META_GENERIC ("PHYS-PORT-ID"),        /* 20 */
	NMC_META_GENERIC ("CONNECTION"),          /* 21 */
	NMC_META_GENERIC ("CON-UUID"),            /* 22 */
	NMC_META_GENERIC ("CON-PATH"),            /* 23 */
	NMC_META_GENERIC ("METERED"),             /* 24 */
	NULL,
};
#define NMC_FIELDS_DEV_SHOW_GENERAL_COMMON  "NAME,DEVICE,TYPE,VENDOR,PRODUCT,DRIVER,HWADDR,STATE"

const NmcMetaGenericInfo *const nmc_fields_dev_show_connections[] = {
	NMC_META_GENERIC ("NAME"),                         /* 0 */
	NMC_META_GENERIC ("AVAILABLE-CONNECTION-PATHS"),   /* 1 */
	NMC_META_GENERIC ("AVAILABLE-CONNECTIONS"),        /* 2 */
	NULL,
};
#define NMC_FIELDS_DEV_SHOW_CONNECTIONS_COMMON  "NAME,AVAILABLE-CONNECTION-PATHS,AVAILABLE-CONNECTIONS"

const NmcMetaGenericInfo *const nmc_fields_dev_show_cap[] = {
	NMC_META_GENERIC ("NAME"),             /* 0 */
	NMC_META_GENERIC ("CARRIER-DETECT"),   /* 1 */
	NMC_META_GENERIC ("SPEED"),            /* 2 */
	NMC_META_GENERIC ("IS-SOFTWARE"),      /* 3 */
	NMC_META_GENERIC ("SRIOV"),            /* 4 */
	NULL,
};
#define NMC_FIELDS_DEV_SHOW_CAP_COMMON  "NAME,CARRIER-DETECT,SPEED,IS-SOFTWARE"

const NmcMetaGenericInfo *const nmc_fields_dev_show_wired_prop[] = {
	NMC_META_GENERIC ("NAME"),               /* 0 */
	NMC_META_GENERIC ("CARRIER"),            /* 1 */
	NMC_META_GENERIC ("S390-SUBCHANNELS"),   /* 2 */
	NULL,
};
#define NMC_FIELDS_DEV_SHOW_WIRED_PROP_COMMON  "NAME,CARRIER,S390-SUBCHANNELS"

const NmcMetaGenericInfo *const nmc_fields_dev_show_wifi_prop[] = {
	NMC_META_GENERIC ("NAME"),    /* 0 */
	NMC_META_GENERIC ("WEP"),     /* 1 */
	NMC_META_GENERIC ("WPA"),     /* 2 */
	NMC_META_GENERIC ("WPA2"),    /* 3 */
	NMC_META_GENERIC ("TKIP"),    /* 4 */
	NMC_META_GENERIC ("CCMP"),    /* 5 */
	NMC_META_GENERIC ("AP"),      /* 6 */
	NMC_META_GENERIC ("ADHOC"),   /* 7 */
	NMC_META_GENERIC ("2GHZ"),    /* 8 */
	NMC_META_GENERIC ("5GHZ"),    /* 9 */
	NULL,
};
#define NMC_FIELDS_DEV_SHOW_WIFI_PROP_COMMON  "NAME,WEP,WPA,WPA2,TKIP,CCMP,AP,ADHOC"

const NmcMetaGenericInfo *const nmc_fields_dev_show_wimax_prop[] = {
	NMC_META_GENERIC ("NAME"),       /* 0 */
	NMC_META_GENERIC ("CTR-FREQ"),   /* 1 */
	NMC_META_GENERIC ("RSSI"),       /* 2 */
	NMC_META_GENERIC ("CINR"),       /* 3 */
	NMC_META_GENERIC ("TX-POW"),     /* 4 */
	NMC_META_GENERIC ("BSID"),       /* 5 */
	NULL,
};
#define NMC_FIELDS_DEV_SHOW_WIMAX_PROP_COMMON  "NAME,CTR-FREQ,RSSI,CINR,TX-POW,BSID"

const NmcMetaGenericInfo *const nmc_fields_dev_wifi_list[] = {
	NMC_META_GENERIC ("NAME"),        /* 0 */
	NMC_META_GENERIC ("SSID"),        /* 1 */
	NMC_META_GENERIC ("SSID-HEX"),    /* 2 */
	NMC_META_GENERIC ("BSSID"),       /* 3 */
	NMC_META_GENERIC ("MODE"),        /* 4 */
	NMC_META_GENERIC ("CHAN"),        /* 5 */
	NMC_META_GENERIC ("FREQ"),        /* 6 */
	NMC_META_GENERIC ("RATE"),        /* 7 */
	NMC_META_GENERIC ("SIGNAL"),      /* 8 */
	NMC_META_GENERIC ("BARS"),        /* 9 */
	NMC_META_GENERIC ("SECURITY"),    /* 10 */
	NMC_META_GENERIC ("WPA-FLAGS"),   /* 11 */
	NMC_META_GENERIC ("RSN-FLAGS"),   /* 12 */
	NMC_META_GENERIC ("DEVICE"),      /* 13 */
	NMC_META_GENERIC ("ACTIVE"),      /* 14 */
	NMC_META_GENERIC ("IN-USE"),      /* 15 */
	NMC_META_GENERIC ("DBUS-PATH"),   /* 16 */
	NULL,
};
#define NMC_FIELDS_DEV_WIFI_LIST_COMMON        "IN-USE,SSID,MODE,CHAN,RATE,SIGNAL,BARS,SECURITY"
#define NMC_FIELDS_DEV_WIFI_LIST_FOR_DEV_LIST  "NAME,"NMC_FIELDS_DEV_WIFI_LIST_COMMON

const NmcMetaGenericInfo *const nmc_fields_dev_wimax_list[] = {
	NMC_META_GENERIC ("NAME"),        /* 0 */
	NMC_META_GENERIC ("NSP"),         /* 1 */
	NMC_META_GENERIC ("SIGNAL"),      /* 2 */
	NMC_META_GENERIC ("TYPE"),        /* 3 */
	NMC_META_GENERIC ("DEVICE"),      /* 4 */
	NMC_META_GENERIC ("ACTIVE"),      /* 5 */
	NMC_META_GENERIC ("DBUS-PATH"),   /* 6 */
	NULL,
};
#define NMC_FIELDS_DEV_WIMAX_LIST_COMMON        "NSP,SIGNAL,TYPE,DEVICE,ACTIVE"
#define NMC_FIELDS_DEV_WIMAX_LIST_FOR_DEV_LIST  "NAME,"NMC_FIELDS_DEV_WIMAX_LIST_COMMON

const NmcMetaGenericInfo *const nmc_fields_dev_show_master_prop[] = {
	NMC_META_GENERIC ("NAME"),     /* 0 */
	NMC_META_GENERIC ("SLAVES"),   /* 1 */
	NULL,
};
#define NMC_FIELDS_DEV_SHOW_MASTER_PROP_COMMON  "NAME,SLAVES"

const NmcMetaGenericInfo *const nmc_fields_dev_show_team_prop[] = {
	NMC_META_GENERIC ("NAME"),     /* 0 */
	NMC_META_GENERIC ("SLAVES"),   /* 1 */
	NMC_META_GENERIC ("CONFIG"),   /* 2 */
	NULL,
};
#define NMC_FIELDS_DEV_SHOW_TEAM_PROP_COMMON  "NAME,SLAVES,CONFIG"

const NmcMetaGenericInfo *const nmc_fields_dev_show_vlan_prop[] = {
	NMC_META_GENERIC ("NAME"),     /* 0 */
	NMC_META_GENERIC ("PARENT"),   /* 1 */
	NMC_META_GENERIC ("ID"),       /* 2 */
	NULL,
};
#define NMC_FIELDS_DEV_SHOW_VLAN_PROP_COMMON  "NAME,PARENT,ID"

const NmcMetaGenericInfo *const nmc_fields_dev_show_bluetooth[] = {
	NMC_META_GENERIC ("NAME"),           /* 0 */
	NMC_META_GENERIC ("CAPABILITIES"),   /* 1 */
	NULL,
};
#define NMC_FIELDS_DEV_SHOW_BLUETOOTH_COMMON  "NAME,CAPABILITIES"

/* Available sections for 'device show' */
const NmcMetaGenericInfo *const nmc_fields_dev_show_sections[] = {
	NMC_META_GENERIC_WITH_NESTED ("GENERAL",           nmc_fields_dev_show_general + 1),      /* 0 */
	NMC_META_GENERIC_WITH_NESTED ("CAPABILITIES",      nmc_fields_dev_show_cap + 1),          /* 1 */
	NMC_META_GENERIC_WITH_NESTED ("WIFI-PROPERTIES",   nmc_fields_dev_show_wifi_prop + 1),    /* 2 */
	NMC_META_GENERIC_WITH_NESTED ("AP",                nmc_fields_dev_wifi_list + 1),         /* 3 */
	NMC_META_GENERIC_WITH_NESTED ("WIRED-PROPERTIES",  nmc_fields_dev_show_wired_prop + 1),   /* 4 */
	NMC_META_GENERIC_WITH_NESTED ("WIMAX-PROPERTIES",  nmc_fields_dev_show_wimax_prop + 1),   /* 5 */
	NMC_META_GENERIC_WITH_NESTED ("NSP",               nmc_fields_dev_wimax_list + 1),        /* 6 */
	NMC_META_GENERIC_WITH_NESTED ("IP4",               metagen_ip4_config),                   /* 7 */
	NMC_META_GENERIC_WITH_NESTED ("DHCP4",             nmc_fields_dhcp4_config + 1),          /* 8 */
	NMC_META_GENERIC_WITH_NESTED ("IP6",               nmc_fields_ip6_config + 1),            /* 9 */
	NMC_META_GENERIC_WITH_NESTED ("DHCP6",             nmc_fields_dhcp6_config + 1),          /* 10 */
	NMC_META_GENERIC_WITH_NESTED ("BOND",              nmc_fields_dev_show_master_prop + 1),  /* 11 */
	NMC_META_GENERIC_WITH_NESTED ("TEAM",              nmc_fields_dev_show_team_prop + 1),    /* 12 */
	NMC_META_GENERIC_WITH_NESTED ("BRIDGE",            nmc_fields_dev_show_master_prop + 1),  /* 13 */
	NMC_META_GENERIC_WITH_NESTED ("VLAN",              nmc_fields_dev_show_vlan_prop + 1),    /* 14 */
	NMC_META_GENERIC_WITH_NESTED ("BLUETOOTH",         nmc_fields_dev_show_bluetooth + 1),    /* 15 */
	NMC_META_GENERIC_WITH_NESTED ("CONNECTIONS",       nmc_fields_dev_show_connections + 1),  /* 16 */
	NULL,
};
#define NMC_FIELDS_DEV_SHOW_SECTIONS_COMMON  "GENERAL.DEVICE,GENERAL.TYPE,GENERAL.HWADDR,GENERAL.MTU,GENERAL.STATE,"\
                                             "GENERAL.CONNECTION,GENERAL.CON-PATH,WIRED-PROPERTIES,IP4,IP6"

const NmcMetaGenericInfo *const nmc_fields_dev_lldp_list[] = {
	NMC_META_GENERIC ("NAME"),                      /* 0 */
	NMC_META_GENERIC ("DEVICE"),                    /* 1 */
	NMC_META_GENERIC ("CHASSIS-ID"),                /* 2 */
	NMC_META_GENERIC ("PORT-ID"),                   /* 3 */
	NMC_META_GENERIC ("PORT-DESCRIPTION"),          /* 4 */
	NMC_META_GENERIC ("SYSTEM-NAME"),               /* 5 */
	NMC_META_GENERIC ("SYSTEM-DESCRIPTION"),        /* 6 */
	NMC_META_GENERIC ("SYSTEM-CAPABILITIES"),       /* 7 */
	NMC_META_GENERIC ("IEEE-802-1-PVID"),           /* 8 */
	NMC_META_GENERIC ("IEEE-802-1-PPVID"),          /* 9 */
	NMC_META_GENERIC ("IEEE-802-1-PPVID-FLAGS"),    /* 10 */
	NMC_META_GENERIC ("IEEE-802-1-VID"),            /* 11 */
	NMC_META_GENERIC ("IEEE-802-1-VLAN-NAME"),      /* 12 */
	NMC_META_GENERIC ("DESTINATION"),               /* 13 */
	NMC_META_GENERIC ("CHASSIS-ID-TYPE"),           /* 14 */
	NMC_META_GENERIC ("PORT-ID-TYPE"),              /* 15 */
	NULL,
};
#define NMC_FIELDS_DEV_LLDP_LIST_COMMON  "DEVICE,CHASSIS-ID,PORT-ID,PORT-DESCRIPTION,SYSTEM-NAME,SYSTEM-DESCRIPTION," \
                                         "SYSTEM-CAPABILITIES"

static guint progress_id = 0;  /* ID of event source for displaying progress */

static void
usage (void)
{
	g_printerr (_("Usage: nmcli device { COMMAND | help }\n\n"
	              "COMMAND := { status | show | set | connect | reapply | modify | disconnect | delete | monitor | wifi | lldp }\n\n"
	              "  status\n\n"
	              "  show [<ifname>]\n\n"
	              "  set [ifname] <ifname> [autoconnect yes|no] [managed yes|no]\n\n"
	              "  connect <ifname>\n\n"
	              "  reapply <ifname>\n\n"
	              "  modify <ifname> ([+|-]<setting>.<property> <value>)+\n\n"
	              "  disconnect <ifname> ...\n\n"
	              "  delete <ifname> ...\n\n"
	              "  monitor <ifname> ...\n\n"
	              "  wifi [list [ifname <ifname>] [bssid <BSSID>]]\n\n"
	              "  wifi connect <(B)SSID> [password <password>] [wep-key-type key|phrase] [ifname <ifname>]\n"
	              "                         [bssid <BSSID>] [name <name>] [private yes|no] [hidden yes|no]\n\n"
	              "  wifi hotspot [ifname <ifname>] [con-name <name>] [ssid <SSID>] [band a|bg] [channel <channel>] [password <password>]\n\n"
	              "  wifi rescan [ifname <ifname>] [[ssid <SSID to scan>] ...]\n\n"
	              "  lldp [list [ifname <ifname>]]\n\n"
	              ));
}

static void
usage_device_status (void)
{
	g_printerr (_("Usage: nmcli device status { help }\n"
	              "\n"
	              "Show status for all devices.\n"
	              "By default, the following columns are shown:\n"
	              " DEVICE     - interface name\n"
	              " TYPE       - device type\n"
	              " STATE      - device state\n"
	              " CONNECTION - connection activated on device (if any)\n"
	              "Displayed columns can be changed using '--fields' global option. 'status' is\n"
	              "the default command, which means 'nmcli device' calls 'nmcli device status'.\n\n"));
}

static void
usage_device_show (void)
{
	g_printerr (_("Usage: nmcli device show { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [<ifname>]\n"
	              "\n"
	              "Show details of device(s).\n"
	              "The command lists details for all devices, or for a given device.\n\n"));
}

static void
usage_device_connect (void)
{
	g_printerr (_("Usage: nmcli device connect { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := <ifname>\n"
	              "\n"
	              "Connect the device.\n"
	              "NetworkManager will try to find a suitable connection that will be activated.\n"
	              "It will also consider connections that are not set to auto-connect.\n\n"));
}

static void
usage_device_reapply (void)
{
	g_printerr (_("Usage: nmcli device reapply { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := <ifname>\n"
	              "\n"
	              "Attempts to update device with changes to the currently active connection\n"
                      "made since it was last applied.\n\n"));
}

static void
usage_device_modify (void)
{
	g_printerr (_("Usage: nmcli device modify { ARGUMENTS | --help }\n"
	              "\n"
	              "ARGUMENTS := <ifname> ([+|-]<setting>.<property> <value>)+\n"
	              "\n"
	              "Modify one or more properties currently active on the device without modifying\n"
	              "the connection profile. The changes have immediate effect. For multi-valued\n"
	              "properties you can use optional '+' or '-' prefix to the property name.\n"
	              "The '+' sign allows appending items instead of overwriting the whole value.\n"
	              "The '-' sign allows removing selected items instead of the whole value.\n"
	              "\n"
	              "Examples:\n"
	              "nmcli dev mod em1 ipv4.method manual ipv4.addr \"192.168.1.2/24, 10.10.1.5/8\"\n"
	              "nmcli dev mod em1 +ipv4.dns 8.8.4.4\n"
	              "nmcli dev mod em1 -ipv4.dns 1\n"
	              "nmcli dev mod em1 -ipv6.addr \"abbe::cafe/56\"\n"));
}

static void
usage_device_disconnect (void)
{
	g_printerr (_("Usage: nmcli device disconnect { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := <ifname> ...\n"
	              "\n"
	              "Disconnect devices.\n"
	              "The command disconnects the device and prevents it from auto-activating\n"
	              "further connections without user/manual intervention.\n\n"));
}

static void
usage_device_delete (void)
{
	g_printerr (_("Usage: nmcli device delete { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := <ifname> ...\n"
	              "\n"
	              "Delete the software devices.\n"
	              "The command removes the interfaces. It only works for software devices\n"
	              "(like bonds, bridges, etc.). Hardware devices cannot be deleted by the\n"
	              "command.\n\n"));
}

static void
usage_device_set (void)
{
	g_printerr (_("Usage: nmcli device set { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := DEVICE { PROPERTY [ PROPERTY ... ] }\n"
	              "DEVICE    := [ifname] <ifname> \n"
	              "PROPERTY  := { autoconnect { yes | no } |\n"
	              "             { managed { yes | no }\n"
	              "\n"
	              "Modify device properties.\n\n"));
}

static void
usage_device_monitor (void)
{
	g_printerr (_("Usage: nmcli device monitor { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [<ifname>] ...\n"
	              "\n"
	              "Monitor device activity.\n"
	              "This command prints a line whenever the specified devices change state.\n"
	              "Monitors all devices in case no interface is specified.\n\n"));
}

static void
usage_device_wifi (void)
{
	g_printerr (_("Usage: nmcli device wifi { ARGUMENTS | help }\n"
	              "\n"
	              "Perform operation on Wi-Fi devices.\n"
	              "\n"
	              "ARGUMENTS := [list [ifname <ifname>] [bssid <BSSID>]]\n"
	              "\n"
	              "List available Wi-Fi access points. The 'ifname' and 'bssid' options can be\n"
	              "used to list APs for a particular interface, or with a specific BSSID.\n"
	              "\n"
	              "ARGUMENTS := connect <(B)SSID> [password <password>] [wep-key-type key|phrase] [ifname <ifname>]\n"
	              "                     [bssid <BSSID>] [name <name>] [private yes|no] [hidden yes|no]\n"
	              "\n"
	              "Connect to a Wi-Fi network specified by SSID or BSSID. The command creates\n"
	              "a new connection and then activates it on a device. This is a command-line\n"
	              "counterpart of clicking an SSID in a GUI client. The command always creates\n"
	              "a new connection and thus it is mainly useful for connecting to new Wi-Fi\n"
	              "networks. If a connection for the network already exists, it is better to\n"
	              "bring up the existing profile as follows: nmcli con up id <name>. Note that\n"
	              "only open, WEP and WPA-PSK networks are supported at the moment. It is also\n"
	              "assumed that IP configuration is obtained via DHCP.\n"
	              "\n"
	              "ARGUMENTS := hotspot [ifname <ifname>] [con-name <name>] [ssid <SSID>]\n"
	              "                     [band a|bg] [channel <channel>] [password <password>]\n"
	              "\n"
	              "Create a Wi-Fi hotspot. Use 'connection down' or 'device disconnect'\n"
	              "to stop the hotspot.\n"
	              "Parameters of the hotspot can be influenced by the optional parameters:\n"
	              "ifname - Wi-Fi device to use\n"
	              "con-name - name of the created hotspot connection profile\n"
	              "ssid - SSID of the hotspot\n"
	              "band - Wi-Fi band to use\n"
	              "channel - Wi-Fi channel to use\n"
	              "password - password to use for the hotspot\n"
	              "\n"
	              "ARGUMENTS := rescan [ifname <ifname>] [[ssid <SSID to scan>] ...]\n"
	              "\n"
	              "Request that NetworkManager immediately re-scan for available access points.\n"
	              "NetworkManager scans Wi-Fi networks periodically, but in some cases it might\n"
	              "be useful to start scanning manually. 'ssid' allows scanning for a specific\n"
	              "SSID, which is useful for APs with hidden SSIDs. More 'ssid' parameters can be\n"
	              "given. Note that this command does not show the APs,\n"
	              "use 'nmcli device wifi list' for that.\n\n"));
}

static void
usage_device_lldp (void)
{
	g_printerr (_("Usage: nmcli device lldp { ARGUMENTS | help }\n"
	              "\n"
	              "ARGUMENTS := [list [ifname <ifname>]]\n"
	              "\n"
	              "List neighboring devices discovered through LLDP. The 'ifname' option can be\n"
	              "used to list neighbors for a particular interface.\n\n"));
}

static void
quit (void)
{
	if (progress_id) {
		g_source_remove (progress_id);
		nmc_terminal_erase_line ();
	}

	g_main_loop_quit (loop);
}

static int
compare_devices (const void *a, const void *b)
{
	NMDevice *da = *(NMDevice **)a;
	NMDevice *db = *(NMDevice **)b;
	NMActiveConnection *da_ac;
	NMActiveConnection *db_ac;
	NMIPConfig *da_ip;
	NMIPConfig *db_ip;
	int da_num_addrs;
	int db_num_addrs;
	int cmp;

	/* Sort by later device states first */
	cmp = nm_device_get_state (db) - nm_device_get_state (da);
	if (cmp != 0)
		return cmp;

	da_ac = nm_device_get_active_connection (da);
	db_ac = nm_device_get_active_connection (db);

	/* Prioritize devices with active connections */
	if (da_ac)
		cmp++;
	if (db_ac)
		cmp--;
	if (cmp != 0)
		return cmp;

	/* VPNs go on the top if possible */
	if (da_ac && !nm_active_connection_get_vpn (da_ac))
		cmp++;
	if (db_ac && !nm_active_connection_get_vpn (db_ac))
		cmp--;
	if (cmp != 0)
		return cmp;

	/* Default devices are prioritized */
	if (da_ac && !nm_active_connection_get_default (da_ac))
		cmp++;
	if (db_ac && !nm_active_connection_get_default (db_ac))
		cmp--;
	if (cmp != 0)
		return cmp;

	/* Default IPv6 devices are prioritized */
	if (da_ac && !nm_active_connection_get_default6 (da_ac))
		cmp++;
	if (db_ac && !nm_active_connection_get_default6 (db_ac))
		cmp--;
	if (cmp != 0)
		return cmp;

	/* Sort by number of addresses. */
	da_ip = da_ac ? nm_active_connection_get_ip4_config (da_ac) : NULL;
	da_num_addrs = da_ip ? nm_ip_config_get_addresses (da_ip)->len : 0;
	db_ip = db_ac ? nm_active_connection_get_ip4_config (db_ac) : NULL;
	db_num_addrs = db_ip ? nm_ip_config_get_addresses (db_ip)->len : 0;

	da_ip = da_ac ? nm_active_connection_get_ip6_config (da_ac) : NULL;
	da_num_addrs += da_ip ? nm_ip_config_get_addresses (da_ip)->len : 0;
	db_ip = db_ac ? nm_active_connection_get_ip6_config (db_ac) : NULL;
	db_num_addrs += db_ip ? nm_ip_config_get_addresses (db_ip)->len : 0;

	cmp = db_num_addrs - da_num_addrs;
	if (cmp != 0)
		return cmp;

	/* Fall back to alphanumeric sort by description and interface. */
	cmp = g_strcmp0 (nm_device_get_type_description (da),
	                 nm_device_get_type_description (db));
	if (cmp != 0)
		return cmp;

	return g_strcmp0 (nm_device_get_iface (da),
	                  nm_device_get_iface (db));
}

NMDevice **
nmc_get_devices_sorted (NMClient *client)
{
	const GPtrArray *devs;
	NMDevice **sorted;

	devs = nm_client_get_devices (client);

	sorted = g_new (NMDevice *, devs->len + 1);
	memcpy (sorted, devs->pdata, devs->len * sizeof (NMDevice *));
	sorted[devs->len] = NULL;

	qsort (sorted, devs->len, sizeof (NMDevice *), compare_devices);
	return sorted;
}

static void
complete_device (NMDevice **devices, const char *prefix, gboolean wifi_only)
{
	int i;

	for (i = 0; devices[i]; i++) {
		const char *iface = nm_device_get_iface (devices[i]);

		if (wifi_only && !NM_IS_DEVICE_WIFI (devices[i]))
			continue;

		if (g_str_has_prefix (iface, prefix))
			g_print ("%s\n", iface);
	}
}

void
nmc_complete_device (NMClient *client, const char *prefix, gboolean wifi_only)
{
	gs_free NMDevice **devices = NULL;

	devices = nmc_get_devices_sorted (client);
	complete_device (devices, prefix, wifi_only);
}

static GSList *
get_device_list (NmCli *nmc, int argc, char **argv)
{
	int arg_num = argc;
	char **arg_arr = NULL;
	char **arg_ptr = argv;
	NMDevice **devices;
	GSList *queue = NULL;
	NMDevice *device;
	int i;

	if (argc == 0) {
		if (nmc->ask) {
			char *line = nmc_readline (PROMPT_INTERFACES);
			nmc_string_to_arg_array (line, NULL, FALSE, &arg_arr, &arg_num);
			g_free (line);
			arg_ptr = arg_arr;
		}
		if (arg_num == 0) {
			g_string_printf (nmc->return_text, _("Error: No interface specified."));
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto error;
		}
	}

	devices = nmc_get_devices_sorted (nmc->client);
	while (arg_num > 0) {
		if (arg_num == 1 && nmc->complete)
			complete_device (devices, *arg_ptr, FALSE);

		device = NULL;
		for (i = 0; devices[i]; i++) {
			if (!g_strcmp0 (nm_device_get_iface (devices[i]), *arg_ptr)) {
				device = devices[i];
				break;
			}
		}

		if (device) {
			if (!g_slist_find (queue, device))
				queue = g_slist_prepend (queue, device);
			else
				g_printerr (_("Warning: argument '%s' is duplicated.\n"), *arg_ptr);
		} else {
			if (!nmc->complete)
				g_printerr (_("Error: Device '%s' not found.\n"), *arg_ptr);
			g_string_printf (nmc->return_text, _("Error: not all devices found."));
			nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
		}

		/* Take next argument */
		next_arg (nmc->ask ? NULL : nmc, &arg_num, &arg_ptr, NULL);
	}
	g_free (devices);

error:
	g_strfreev (arg_arr);

	return queue;
}

static NMDevice *
get_device (NmCli *nmc, int *argc, char ***argv, GError **error)
{
	gs_free NMDevice **devices = NULL;
	gs_free char *ifname_ask = NULL;
	const char *ifname = NULL;
	int i;

	if (*argc == 0) {
		if (nmc->ask)
			ifname = ifname_ask = nmc_readline (PROMPT_INTERFACE);

		if (!ifname_ask) {
			g_set_error_literal (error, NMCLI_ERROR, NMC_RESULT_ERROR_USER_INPUT,
			                     _("No interface specified"));
			return NULL;
		}
	} else {
		ifname = **argv;
		next_arg (nmc, argc, argv, NULL);
	}

	devices = nmc_get_devices_sorted (nmc->client);
	for (i = 0; devices[i]; i++) {
		if (!g_strcmp0 (nm_device_get_iface (devices[i]), ifname))
			break;
	}

	if (nmc->complete && !*argc)
		complete_device (devices, ifname, FALSE);

	if (devices[i] == NULL) {
		g_set_error (error, NMCLI_ERROR, NMC_RESULT_ERROR_NOT_FOUND,
		             _("Device '%s' not found"), ifname);
	}

	return devices[i];
}

static int
compare_aps (gconstpointer a, gconstpointer b, gpointer user_data)
{
	NMAccessPoint *apa = *(NMAccessPoint **)a;
	NMAccessPoint *apb = *(NMAccessPoint **)b;
	int cmp;

	cmp = nm_access_point_get_strength (apb) - nm_access_point_get_strength (apa);
	if (cmp != 0)
		return cmp;

	cmp = nm_access_point_get_frequency (apa) - nm_access_point_get_frequency (apb);
	if (cmp != 0)
		return cmp;

	return nm_access_point_get_max_bitrate (apb) - nm_access_point_get_max_bitrate (apa);
}

static GPtrArray *
sort_access_points (const GPtrArray *aps)
{
	GPtrArray *sorted;
	int i;

	g_return_val_if_fail (aps, NULL);

	sorted = g_ptr_array_sized_new (aps->len);
	for (i = 0; i < aps->len; i++)
		g_ptr_array_add (sorted, aps->pdata[i]);
	g_ptr_array_sort_with_data (sorted, compare_aps, NULL);
	return sorted;
}

static void
wifi_signal_to_color (guint8 strength, NMMetaTermColor *color, NMMetaTermFormat *color_fmt)
{
	*color = NM_META_TERM_COLOR_NORMAL;
	*color_fmt = NM_META_TERM_FORMAT_NORMAL;

	if (strength > 80)
		*color = NM_META_TERM_COLOR_GREEN;
	else if (strength > 55)
		*color = NM_META_TERM_COLOR_YELLOW;
	else if (strength > 30)
		*color = NM_META_TERM_COLOR_MAGENTA;
	else if (strength > 5)
		*color = NM_META_TERM_COLOR_CYAN;
	else
		*color_fmt = NM_META_TERM_FORMAT_DIM;
}

static char *
ap_wpa_rsn_flags_to_string (NM80211ApSecurityFlags flags)
{
	char *flags_str[16]; /* Enough space for flags and terminating NULL */
	char *ret_str;
	int i = 0;

	if (flags & NM_802_11_AP_SEC_PAIR_WEP40)
		flags_str[i++] = g_strdup ("pair_wpe40");
	if (flags & NM_802_11_AP_SEC_PAIR_WEP104)
		flags_str[i++] = g_strdup ("pair_wpe104");
	if (flags & NM_802_11_AP_SEC_PAIR_TKIP)
		flags_str[i++] = g_strdup ("pair_tkip");
	if (flags & NM_802_11_AP_SEC_PAIR_CCMP)
		flags_str[i++] = g_strdup ("pair_ccmp");
	if (flags & NM_802_11_AP_SEC_GROUP_WEP40)
		flags_str[i++] = g_strdup ("group_wpe40");
	if (flags & NM_802_11_AP_SEC_GROUP_WEP104)
		flags_str[i++] = g_strdup ("group_wpe104");
	if (flags & NM_802_11_AP_SEC_GROUP_TKIP)
		flags_str[i++] = g_strdup ("group_tkip");
	if (flags & NM_802_11_AP_SEC_GROUP_CCMP)
		flags_str[i++] = g_strdup ("group_ccmp");
	if (flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)
		flags_str[i++] = g_strdup ("psk");
	if (flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
		flags_str[i++] = g_strdup ("802.1X");

	if (i == 0)
		flags_str[i++] = g_strdup (_("(none)"));

	flags_str[i] = NULL;

	ret_str = g_strjoinv (" ", flags_str);

	i = 0;
	while (flags_str[i])
		g_free (flags_str[i++]);

	return ret_str;
}

typedef struct {
	NmCli *nmc;
	int index;
	guint32 output_flags;
	const char* active_bssid;
	const char* device;
	GPtrArray *output_data;
} APInfo;

static void
fill_output_access_point (gpointer data, gpointer user_data)
{
	NMAccessPoint *ap = NM_ACCESS_POINT (data);
	APInfo *info = (APInfo *) user_data;
	NmcOutputField *arr;
	gboolean active = FALSE;
	NM80211ApFlags flags;
	NM80211ApSecurityFlags wpa_flags, rsn_flags;
	guint32 freq, bitrate;
	guint8 strength;
	GBytes *ssid;
	const char *bssid;
	NM80211Mode mode;
	char *channel_str, *freq_str, *ssid_str = NULL, *ssid_hex_str = NULL,
	     *bitrate_str, *strength_str, *wpa_flags_str, *rsn_flags_str;
	GString *security_str;
	char *ap_name;
	const char *sig_bars;
	NMMetaTermColor color;
	NMMetaTermFormat color_fmt;

	if (info->active_bssid) {
		const char *current_bssid = nm_access_point_get_bssid (ap);
		if (current_bssid && !strcmp (current_bssid, info->active_bssid))
			active = TRUE;
	}

	/* Get AP properties */
	flags = nm_access_point_get_flags (ap);
	wpa_flags = nm_access_point_get_wpa_flags (ap);
	rsn_flags = nm_access_point_get_rsn_flags (ap);
	ssid = nm_access_point_get_ssid (ap);
	bssid = nm_access_point_get_bssid (ap);
	freq = nm_access_point_get_frequency (ap);
	mode = nm_access_point_get_mode (ap);
	bitrate = nm_access_point_get_max_bitrate (ap);
	strength = MIN (nm_access_point_get_strength (ap), 100);

	/* Convert to strings */
	if (ssid) {
		const guint8 *ssid_data;
		gsize ssid_len;

		ssid_data = g_bytes_get_data (ssid, &ssid_len);
		ssid_str = nm_utils_ssid_to_utf8 (ssid_data, ssid_len);
		ssid_hex_str = ssid_to_hex ((const char *) ssid_data, ssid_len);
	}
	channel_str = g_strdup_printf ("%u", nm_utils_wifi_freq_to_channel (freq));
	freq_str = g_strdup_printf (_("%u MHz"), freq);
	bitrate_str = g_strdup_printf (_("%u Mbit/s"), bitrate/1000);
	strength_str = g_strdup_printf ("%u", strength);
	wpa_flags_str = ap_wpa_rsn_flags_to_string (wpa_flags);
	rsn_flags_str = ap_wpa_rsn_flags_to_string (rsn_flags);
	sig_bars = nm_utils_wifi_strength_bars (strength);

	security_str = g_string_new (NULL);

	if (   (flags & NM_802_11_AP_FLAGS_PRIVACY)
	    && (wpa_flags == NM_802_11_AP_SEC_NONE)
	    && (rsn_flags == NM_802_11_AP_SEC_NONE)) {
		g_string_append (security_str, _("WEP"));
		g_string_append_c (security_str, ' ');
	}
	if (wpa_flags != NM_802_11_AP_SEC_NONE) {
		g_string_append (security_str, _("WPA1"));
		g_string_append_c (security_str, ' ');
	}
	if (rsn_flags != NM_802_11_AP_SEC_NONE) {
		g_string_append (security_str, _("WPA2"));
		g_string_append_c (security_str, ' ');
	}
	if (   (wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
	    || (rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)) {
		g_string_append   (security_str, _("802.1X"));
		g_string_append_c (security_str, ' ');
	}

	if (security_str->len > 0)
		g_string_truncate (security_str, security_str->len-1);  /* Chop off last space */

	arr = nmc_dup_fields_array ((const NMMetaAbstractInfo *const*) nmc_fields_dev_wifi_list,
	                            info->output_flags);

	ap_name = g_strdup_printf ("AP[%d]", info->index++); /* AP */
	set_val_str  (arr, 0, ap_name);
	set_val_str  (arr, 1, ssid_str);
	set_val_str  (arr, 2, ssid_hex_str);
	set_val_strc (arr, 3, bssid);
	set_val_strc (arr, 4, mode == NM_802_11_MODE_ADHOC ? _("Ad-Hoc")
	                    : mode == NM_802_11_MODE_INFRA ? _("Infra")
	                    : _("N/A"));
	set_val_str  (arr, 5, channel_str);
	set_val_str  (arr, 6, freq_str);
	set_val_str  (arr, 7, bitrate_str);
	set_val_str  (arr, 8, strength_str);
	set_val_strc (arr, 9, sig_bars);
	set_val_str  (arr, 10, security_str->str);
	set_val_str  (arr, 11, wpa_flags_str);
	set_val_str  (arr, 12, rsn_flags_str);
	set_val_strc (arr, 13, info->device);
	set_val_strc (arr, 14, active ? _("yes") : _("no"));
	set_val_strc (arr, 15, active ? "*" : " ");
	set_val_strc (arr, 16, nm_object_get_path (NM_OBJECT (ap)));

	/* Set colors */
	wifi_signal_to_color (strength, &color, &color_fmt);
	set_val_color_all (arr, color);
	set_val_color_fmt_all (arr, color_fmt);
	if (active)
		arr[15].color = NM_META_TERM_COLOR_GREEN;

	g_ptr_array_add (info->output_data, arr);

	g_string_free (security_str, FALSE);
}

static char *
bluetooth_caps_to_string (NMBluetoothCapabilities caps)
{
	char *caps_str[8]; /* Enough space for caps and terminating NULL */
	char *ret_str;
	int i = 0;

	if (caps & NM_BT_CAPABILITY_DUN)
		caps_str[i++] = g_strdup ("DUN");
	if (caps & NM_BT_CAPABILITY_NAP)
		caps_str[i++] = g_strdup ("NAP");

	if (i == 0)
		caps_str[i++] = g_strdup (_("(none)"));

	caps_str[i] = NULL;

	ret_str = g_strjoinv (" ", caps_str);

	i = 0;
	while (caps_str[i])
		g_free (caps_str[i++]);

	return ret_str;
}

static char *
construct_header_name (const char *base, const char *spec)
{
	if (spec == NULL)
		return g_strdup (base);

	return g_strdup_printf ("%s (%s)", base, spec);
}

static const char *
get_active_connection_id (NMDevice *device)
{
	NMActiveConnection *ac;

	ac = nm_device_get_active_connection (device);
	if (!ac)
		return NULL;

	return nm_active_connection_get_id (ac);
}

static gboolean
print_bond_bridge_info (NMDevice *device,
                        NmCli *nmc,
                        const char *group_prefix,
                        const char *one_field)
{
	const GPtrArray *slaves = NULL;
	GString *slaves_str;
	int idx;
	const NMMetaAbstractInfo *const*tmpl;
	NmcOutputField *arr;
	NMC_OUTPUT_DATA_DEFINE_SCOPED (out);

	if (NM_IS_DEVICE_BOND (device))
		slaves = nm_device_bond_get_slaves (NM_DEVICE_BOND (device));
	else if (NM_IS_DEVICE_BRIDGE (device))
		slaves = nm_device_bridge_get_slaves (NM_DEVICE_BRIDGE (device));
	else
		g_return_val_if_reached (FALSE);

	slaves_str = g_string_new (NULL);
	for (idx = 0; slaves && idx < slaves->len; idx++) {
		NMDevice *slave = g_ptr_array_index (slaves, idx);
		const char *iface = nm_device_get_iface (slave);

		if (iface) {
			g_string_append (slaves_str, iface);
			g_string_append_c (slaves_str, ' ');
		}
	}
	if (slaves_str->len > 0)
		g_string_truncate (slaves_str, slaves_str->len-1);  /* Chop off last space */

	tmpl = (const NMMetaAbstractInfo *const*) nmc_fields_dev_show_master_prop;
	out_indices = parse_output_fields (one_field,
	                                   tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (out.output_data, arr);

	arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_strc (arr, 0, group_prefix);     /* i.e. BOND, TEAM, BRIDGE */
	set_val_str  (arr, 1, slaves_str->str);
	g_ptr_array_add (out.output_data, arr);

	print_data_prepare_width (out.output_data);
	print_data (&nmc->nmc_config, out_indices, NULL, 0, &out);

	g_string_free (slaves_str, FALSE);

	return TRUE;
}

static char *
sanitize_team_config (const char *config)
{
	char *ret;
	int i;

	if (!config)
		return NULL;

	ret = g_strdup (config);

	for (i = 0; i < strlen (ret); i++) {
		if (ret[i] == '\n')
			ret[i] = ' ';
	}

	return ret;
}

static gboolean
print_team_info (NMDevice *device,
                 NmCli *nmc,
                 const char *group_prefix,
                 const char *one_field)
{
	const GPtrArray *slaves = NULL;
	GString *slaves_str;
	int idx;
	const NMMetaAbstractInfo *const* tmpl;
	NmcOutputField *arr;
	NMC_OUTPUT_DATA_DEFINE_SCOPED (out);

	if (NM_IS_DEVICE_TEAM (device))
		slaves = nm_device_team_get_slaves (NM_DEVICE_TEAM (device));
	else
		g_return_val_if_reached (FALSE);

	slaves_str = g_string_new (NULL);
	for (idx = 0; slaves && idx < slaves->len; idx++) {
		NMDevice *slave = g_ptr_array_index (slaves, idx);
		const char *iface = nm_device_get_iface (slave);

		if (iface) {
			g_string_append (slaves_str, iface);
			g_string_append_c (slaves_str, ' ');
		}
	}
	if (slaves_str->len > 0)
		g_string_truncate (slaves_str, slaves_str->len-1);  /* Chop off last space */

	tmpl = (const NMMetaAbstractInfo *const*) nmc_fields_dev_show_team_prop;
	out_indices = parse_output_fields (one_field,
	                                   tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (out.output_data, arr);

	arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_strc (arr, 0, group_prefix);     /* TEAM */
	set_val_str  (arr, 1, slaves_str->str);
	set_val_str (arr, 2, sanitize_team_config (nm_device_team_get_config (NM_DEVICE_TEAM (device))));
	g_ptr_array_add (out.output_data, arr);

	print_data_prepare_width (out.output_data);
	print_data (&nmc->nmc_config, out_indices, NULL, 0, &out);

	g_string_free (slaves_str, FALSE);

	return TRUE;
}

static gboolean
show_device_info (NMDevice *device, NmCli *nmc)
{
	GError *error = NULL;
	const char *hwaddr = NULL;
	NMDeviceState state = NM_DEVICE_STATE_UNKNOWN;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	NMDeviceCapabilities caps;
	NMActiveConnection *acon;
	guint32 speed;
	char *speed_str, *state_str, *reason_str, *mtu_str;
	GArray *sections_array;
	int k;
	const char *fields_str = NULL;
	const NMMetaAbstractInfo *const*tmpl;
	NmcOutputField *arr;
	gboolean was_output = FALSE;
	NMIPConfig *cfg4, *cfg6;
	NMDhcpConfig *dhcp4, *dhcp6;
	const char *base_hdr = _("Device details");
	GPtrArray *fields_in_section = NULL;

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = NMC_FIELDS_DEV_SHOW_SECTIONS_COMMON;
	else if (strcasecmp (nmc->required_fields, "all") == 0) {
	} else
		fields_str = nmc->required_fields;

	sections_array = parse_output_fields (fields_str, (const NMMetaAbstractInfo *const*) nmc_fields_dev_show_sections, TRUE, &fields_in_section, &error);
	if (error) {
		g_string_printf (nmc->return_text, _("Error: 'device show': %s"), error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return FALSE;
	}

	{
		gs_unref_array GArray *out_indices = NULL;
		gs_free char *header_name = NULL;
		gs_free NmcOutputField *row = NULL;
		int i;

		/* Main header (pretty only) */
		header_name = construct_header_name (base_hdr, nm_device_get_iface (device));

		/* Lazy way to retrieve sorted array from 0 to the number of dev fields */
		out_indices = parse_output_fields (NULL,
		                                   (const NMMetaAbstractInfo *const*) nmc_fields_dev_show_general,
		                                   FALSE, NULL, NULL);

		row = g_new0 (NmcOutputField, G_N_ELEMENTS (nmc_fields_dev_show_general));
		for (i = 0; i < G_N_ELEMENTS (nmc_fields_dev_show_general); i++)
			row[i].info = (const NMMetaAbstractInfo *) &nmc_fields_dev_show_general[i];

		print_required_fields (&nmc->nmc_config, NMC_OF_FLAG_MAIN_HEADER_ONLY,
		                       out_indices, header_name,
		                       0, row);
	}

	/* Loop through the required sections and print them. */
	for (k = 0; k < sections_array->len; k++) {
		int section_idx = g_array_index (sections_array, int, k);
		char *section_fld = (char *) g_ptr_array_index (fields_in_section, k);

		if (nmc->nmc_config.print_output != NMC_PRINT_TERSE && !nmc->nmc_config.multiline_output && was_output)
			g_print ("\n"); /* Print empty line between groups in tabular mode */

		was_output = FALSE;

		state = nm_device_get_state (device);
		reason = nm_device_get_state_reason (device);

		/* section GENERAL */
		if (!strcasecmp (nmc_fields_dev_show_sections[section_idx]->name, nmc_fields_dev_show_sections[0]->name)) {
			NMC_OUTPUT_DATA_DEFINE_SCOPED (out);

			tmpl = (const NMMetaAbstractInfo *const*) nmc_fields_dev_show_general;
			out_indices = parse_output_fields (section_fld,
			                                   tmpl, FALSE, NULL, NULL);
			arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_FIELD_NAMES);
			g_ptr_array_add (out.output_data, arr);

			state_str = g_strdup_printf ("%d (%s)", state, nmc_device_state_to_string (state));
			reason_str = g_strdup_printf ("%d (%s)", reason, nmc_device_reason_to_string (reason));
			hwaddr = nm_device_get_hw_address (device);
			mtu_str = g_strdup_printf ("%u", nm_device_get_mtu (device));
			acon = nm_device_get_active_connection (device);

			arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_SECTION_PREFIX);
			set_val_strc (arr, 0, nmc_fields_dev_show_sections[0]->name);  /* "GENERAL"*/
			set_val_strc (arr, 1, nm_device_get_iface (device));
			set_val_strc (arr, 2, nm_device_get_type_description (device));
			set_val_strc (arr, 3, G_OBJECT_TYPE_NAME (device));
			set_val_strc (arr, 4, nm_device_get_vendor (device));
			set_val_strc (arr, 5, nm_device_get_product (device));
			set_val_strc (arr, 6, nm_device_get_driver (device) ? nm_device_get_driver (device) : _("(unknown)"));
			set_val_strc (arr, 7, nm_device_get_driver_version (device));
			set_val_strc (arr, 8, nm_device_get_firmware_version (device));
			set_val_strc (arr, 9, hwaddr ? hwaddr : _("(unknown)"));
			set_val_str  (arr, 10, mtu_str);
			set_val_str  (arr, 11, state_str);
			set_val_str  (arr, 12, reason_str);
			set_val_strc (arr, 13, nm_device_get_udi (device));
			set_val_strc (arr, 14, nm_device_get_ip_iface (device));
			set_val_strc (arr, 15, nm_device_is_software (device) ? _("yes") : _("no"));
			set_val_strc (arr, 16, nm_device_get_managed (device) ? _("yes") : _("no"));
			set_val_strc (arr, 17, nm_device_get_autoconnect (device) ? _("yes") : _("no"));
			set_val_strc (arr, 18, nm_device_get_firmware_missing (device) ? _("yes") : _("no"));
			set_val_strc (arr, 19, nm_device_get_nm_plugin_missing (device) ? _("yes") : _("no"));
			set_val_strc (arr, 20, nm_device_get_physical_port_id (device));
			set_val_strc (arr, 21, get_active_connection_id (device));
			set_val_strc (arr, 22, acon ? nm_active_connection_get_uuid (acon) : NULL);
			set_val_strc (arr, 23, acon ? nm_object_get_path (NM_OBJECT (acon)) : NULL);
			set_val_strc (arr, 24, nmc_device_metered_to_string (nm_device_get_metered (device)));
			g_ptr_array_add (out.output_data, arr);

			print_data_prepare_width (out.output_data);
			print_data (&nmc->nmc_config, out_indices, NULL, 0, &out);
			was_output = TRUE;
		}

		/* section CAPABILITIES */
		if (!strcasecmp (nmc_fields_dev_show_sections[section_idx]->name, nmc_fields_dev_show_sections[1]->name)) {
			NMC_OUTPUT_DATA_DEFINE_SCOPED (out);

			tmpl = (const NMMetaAbstractInfo *const*) nmc_fields_dev_show_cap;
			out_indices = parse_output_fields (section_fld,
			                                   tmpl, FALSE, NULL, NULL);
			arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_FIELD_NAMES);
			g_ptr_array_add (out.output_data, arr);

			caps = nm_device_get_capabilities (device);
			speed = 0;
			if (NM_IS_DEVICE_ETHERNET (device)) {
				/* Speed in Mb/s */
				speed = nm_device_ethernet_get_speed (NM_DEVICE_ETHERNET (device));
			} else if (NM_IS_DEVICE_WIFI (device)) {
				/* Speed in b/s */
				speed = nm_device_wifi_get_bitrate (NM_DEVICE_WIFI (device));
				speed /= 1000;
			}
			speed_str = speed ? g_strdup_printf (_("%u Mb/s"), speed) : g_strdup (_("unknown"));

			arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_SECTION_PREFIX);
			set_val_strc (arr, 0, nmc_fields_dev_show_sections[1]->name);  /* "CAPABILITIES" */
			set_val_strc (arr, 1, (caps & NM_DEVICE_CAP_CARRIER_DETECT) ? _("yes") : _("no"));
			set_val_str  (arr, 2, speed_str);
			set_val_strc (arr, 3, (caps & NM_DEVICE_CAP_IS_SOFTWARE) ? _("yes") : _("no"));
			set_val_strc (arr, 4, (caps & NM_DEVICE_CAP_SRIOV) ? _("yes") : _("no"));
			g_ptr_array_add (out.output_data, arr);

			print_data_prepare_width (out.output_data);
			print_data (&nmc->nmc_config, out_indices, NULL, 0, &out);
			was_output = TRUE;
		}

		/* Wireless specific information */
		if ((NM_IS_DEVICE_WIFI (device))) {
			NMDeviceWifiCapabilities wcaps;
			NMAccessPoint *active_ap = NULL;
			const char *active_bssid = NULL;
			GPtrArray *aps;

			/* section WIFI-PROPERTIES */
			if (!strcasecmp (nmc_fields_dev_show_sections[section_idx]->name, nmc_fields_dev_show_sections[2]->name)) {
				NMC_OUTPUT_DATA_DEFINE_SCOPED (out);

				wcaps = nm_device_wifi_get_capabilities (NM_DEVICE_WIFI (device));

				tmpl = (const NMMetaAbstractInfo *const*) nmc_fields_dev_show_wifi_prop;
				out_indices = parse_output_fields (section_fld,
				                                   tmpl, FALSE, NULL, NULL);
				arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (out.output_data, arr);

				arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_SECTION_PREFIX);
				set_val_strc (arr, 0, nmc_fields_dev_show_sections[2]->name);  /* "WIFI-PROPERTIES" */
				set_val_strc (arr, 1, (wcaps & (NM_WIFI_DEVICE_CAP_CIPHER_WEP40 | NM_WIFI_DEVICE_CAP_CIPHER_WEP104)) ?
				                        _("yes") : _("no"));
				set_val_strc (arr, 2, (wcaps & NM_WIFI_DEVICE_CAP_WPA) ? _("yes") : _("no"));
				set_val_strc (arr, 3, (wcaps & NM_WIFI_DEVICE_CAP_RSN) ? _("yes") : _("no"));
				set_val_strc (arr, 4, (wcaps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP) ? _("yes") : _("no"));
				set_val_strc (arr, 5, (wcaps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP) ? _("yes") : _("no"));
				set_val_strc (arr, 6, (wcaps & NM_WIFI_DEVICE_CAP_AP) ? _("yes") : _("no"));
				set_val_strc (arr, 7, (wcaps & NM_WIFI_DEVICE_CAP_ADHOC) ? _("yes") : _("no"));
				set_val_strc (arr, 8, !(wcaps & NM_WIFI_DEVICE_CAP_FREQ_VALID) ? _("unknown") :
				                      ((wcaps & NM_WIFI_DEVICE_CAP_FREQ_2GHZ) ? _("yes") : _("no")));
				set_val_strc (arr, 9, !(wcaps & NM_WIFI_DEVICE_CAP_FREQ_VALID) ? _("unknown") :
				                      ((wcaps & NM_WIFI_DEVICE_CAP_FREQ_5GHZ) ? _("yes") : _("no")));
				g_ptr_array_add (out.output_data, arr);

				print_data_prepare_width (out.output_data);
				print_data (&nmc->nmc_config, out_indices, NULL, 0, &out);
				was_output = TRUE;
			}

			/* section AP */
			if (!strcasecmp (nmc_fields_dev_show_sections[section_idx]->name, nmc_fields_dev_show_sections[3]->name)) {
				NMC_OUTPUT_DATA_DEFINE_SCOPED (out);

				if (state == NM_DEVICE_STATE_ACTIVATED) {
					active_ap = nm_device_wifi_get_active_access_point (NM_DEVICE_WIFI (device));
					active_bssid = active_ap ? nm_access_point_get_bssid (active_ap) : NULL;
				}

				tmpl = (const NMMetaAbstractInfo *const*) nmc_fields_dev_wifi_list;
				out_indices = parse_output_fields (section_fld ? section_fld : NMC_FIELDS_DEV_WIFI_LIST_FOR_DEV_LIST,
				                                   tmpl, FALSE, NULL, NULL);
				arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (out.output_data, arr);

				{
					APInfo info = {
						.nmc = nmc,
						.index = 1,
						.output_flags = NMC_OF_FLAG_SECTION_PREFIX,
						.active_bssid = active_bssid,
						.device = nm_device_get_iface (device),
						.output_data = out.output_data,
					};

					aps = sort_access_points (nm_device_wifi_get_access_points (NM_DEVICE_WIFI (device)));
					g_ptr_array_foreach (aps, fill_output_access_point, &info);
					g_ptr_array_free (aps, FALSE);
				}

				print_data_prepare_width (out.output_data);
				print_data (&nmc->nmc_config, out_indices, NULL, 0, &out);
				was_output = TRUE;
			}
		} else if (NM_IS_DEVICE_ETHERNET (device)) {
			/* WIRED-PROPERTIES */
			if (!strcasecmp (nmc_fields_dev_show_sections[section_idx]->name, nmc_fields_dev_show_sections[4]->name)) {
				NMC_OUTPUT_DATA_DEFINE_SCOPED (out);

				tmpl = (const NMMetaAbstractInfo *const*) nmc_fields_dev_show_wired_prop;
				out_indices = parse_output_fields (section_fld,
				                                   tmpl, FALSE, NULL, NULL);
				arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (out.output_data, arr);

				arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_SECTION_PREFIX);
				set_val_strc (arr, 0, nmc_fields_dev_show_sections[4]->name);  /* "WIRED-PROPERTIES" */
				set_val_strc (arr, 1, (nm_device_ethernet_get_carrier (NM_DEVICE_ETHERNET (device))) ?
				                        _("on") : _("off"));
				set_val_arrc (arr, 2, ((const char **) nm_device_ethernet_get_s390_subchannels (NM_DEVICE_ETHERNET (device))));
				g_ptr_array_add (out.output_data, arr);

				print_data_prepare_width (out.output_data);
				print_data (&nmc->nmc_config, out_indices, NULL, 0, &out);
				was_output = TRUE;
			}
		}

		/* IP configuration info */
		cfg4 = nm_device_get_ip4_config (device);
		cfg6 = nm_device_get_ip6_config (device);
		dhcp4 = nm_device_get_dhcp4_config (device);
		dhcp6 = nm_device_get_dhcp6_config (device);

		/* IP4 */
		if (cfg4 && !strcasecmp (nmc_fields_dev_show_sections[section_idx]->name, nmc_fields_dev_show_sections[7]->name))
			was_output = print_ip4_config (cfg4, &nmc->nmc_config, section_fld);

		/* DHCP4 */
		if (dhcp4 && !strcasecmp (nmc_fields_dev_show_sections[section_idx]->name, nmc_fields_dev_show_sections[8]->name))
			was_output = print_dhcp4_config (dhcp4, &nmc->nmc_config, nmc_fields_dev_show_sections[8]->name, section_fld);

		/* IP6 */
		if (cfg6 && !strcasecmp (nmc_fields_dev_show_sections[section_idx]->name, nmc_fields_dev_show_sections[9]->name))
			was_output = print_ip6_config (cfg6, &nmc->nmc_config, nmc_fields_dev_show_sections[9]->name, section_fld);

		/* DHCP6 */
		if (dhcp6 && !strcasecmp (nmc_fields_dev_show_sections[section_idx]->name, nmc_fields_dev_show_sections[10]->name))
			was_output = print_dhcp6_config (dhcp6, &nmc->nmc_config, nmc_fields_dev_show_sections[10]->name, section_fld);

		/* Bond specific information */
		if (NM_IS_DEVICE_BOND (device)) {
			if (!strcasecmp (nmc_fields_dev_show_sections[section_idx]->name, nmc_fields_dev_show_sections[11]->name))
				was_output = print_bond_bridge_info (device, nmc, nmc_fields_dev_show_sections[11]->name, section_fld);
		}

		/* Team specific information */
		if (NM_IS_DEVICE_TEAM (device)) {
			if (!strcasecmp (nmc_fields_dev_show_sections[section_idx]->name, nmc_fields_dev_show_sections[12]->name))
				was_output = print_team_info (device, nmc, nmc_fields_dev_show_sections[12]->name, section_fld);
		}

		/* Bridge specific information */
		if (NM_IS_DEVICE_BRIDGE (device)) {
			if (!strcasecmp (nmc_fields_dev_show_sections[section_idx]->name, nmc_fields_dev_show_sections[13]->name))
				was_output = print_bond_bridge_info (device, nmc, nmc_fields_dev_show_sections[13]->name, section_fld);
		}

		/* VLAN-specific information */
		if ((NM_IS_DEVICE_VLAN (device))) {
			if (!strcasecmp (nmc_fields_dev_show_sections[section_idx]->name, nmc_fields_dev_show_sections[14]->name)) {
				char * vlan_id_str = g_strdup_printf ("%u", nm_device_vlan_get_vlan_id (NM_DEVICE_VLAN (device)));
				NMDevice *parent = nm_device_vlan_get_parent (NM_DEVICE_VLAN (device));
				NMC_OUTPUT_DATA_DEFINE_SCOPED (out);

				tmpl = (const NMMetaAbstractInfo *const*) nmc_fields_dev_show_vlan_prop;
				out_indices = parse_output_fields (section_fld,
				                                   tmpl, FALSE, NULL, NULL);
				arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (out.output_data, arr);

				arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_SECTION_PREFIX);
				set_val_strc (arr, 0, nmc_fields_dev_show_sections[14]->name);  /* "VLAN" */
				set_val_strc (arr, 1, parent ? nm_device_get_iface (parent) : NULL);
				set_val_str  (arr, 2, vlan_id_str);
				g_ptr_array_add (out.output_data, arr);

				print_data_prepare_width (out.output_data);
				print_data (&nmc->nmc_config, out_indices, NULL, 0, &out);

				was_output = TRUE;
			}
		}

		if (NM_IS_DEVICE_BT (device)) {
			if (!strcasecmp (nmc_fields_dev_show_sections[section_idx]->name, nmc_fields_dev_show_sections[15]->name)) {
				NMC_OUTPUT_DATA_DEFINE_SCOPED (out);

				tmpl = (const NMMetaAbstractInfo *const*) nmc_fields_dev_show_bluetooth;
				out_indices = parse_output_fields (section_fld,
				                                   tmpl, FALSE, NULL, NULL);
				arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (out.output_data, arr);

				arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_SECTION_PREFIX);
				set_val_strc (arr, 0, nmc_fields_dev_show_sections[15]->name);  /* "BLUETOOTH" */
				set_val_str (arr, 1, bluetooth_caps_to_string (nm_device_bt_get_capabilities (NM_DEVICE_BT (device))));
				g_ptr_array_add (out.output_data, arr);

				print_data_prepare_width (out.output_data);
				print_data (&nmc->nmc_config, out_indices, NULL, 0, &out);
				was_output = TRUE;
			}
		}

		/* section CONNECTIONS */
		if (!strcasecmp (nmc_fields_dev_show_sections[section_idx]->name, nmc_fields_dev_show_sections[16]->name)) {
			const GPtrArray *avail_cons;
			GString *ac_paths_str;
			char **ac_arr = NULL;
			int i;
			NMC_OUTPUT_DATA_DEFINE_SCOPED (out);

			tmpl = (const NMMetaAbstractInfo *const*) nmc_fields_dev_show_connections;
			out_indices = parse_output_fields (section_fld,
			                                   tmpl, FALSE, NULL, NULL);
			arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_FIELD_NAMES);
			g_ptr_array_add (out.output_data, arr);

			/* available-connections */
			avail_cons = nm_device_get_available_connections (device);
			ac_paths_str = g_string_new (NULL);
			if (avail_cons->len) {
				ac_arr = g_new (char *, avail_cons->len + 1);
				ac_arr[avail_cons->len] = NULL;
			}
			for (i = 0; i < avail_cons->len; i++) {
				NMRemoteConnection *avail_con = g_ptr_array_index (avail_cons, i);
				const char *ac_path = nm_connection_get_path (NM_CONNECTION (avail_con));
				const char *ac_id = nm_connection_get_id (NM_CONNECTION (avail_con));
				const char *ac_uuid = nm_connection_get_uuid (NM_CONNECTION (avail_con));

				ac_arr[i] = g_strdup_printf ("%s | %s", ac_uuid, ac_id);

				if (i == 0)
					g_string_printf (ac_paths_str, "%s/{", NM_DBUS_PATH_SETTINGS);
				else
					g_string_append_c (ac_paths_str, ',');
				g_string_append (ac_paths_str, strrchr (ac_path, '/') + 1);
			}
			if (ac_paths_str->len > 0)
				g_string_append_c (ac_paths_str, '}');

			arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_SECTION_PREFIX);
			set_val_strc (arr, 0, nmc_fields_dev_show_sections[16]->name);  /* "CONNECTIONS" */
			set_val_str  (arr, 1, ac_paths_str->str);
			set_val_arr  (arr, 2, (ac_arr));
			g_ptr_array_add (out.output_data, arr);

			print_data_prepare_width (out.output_data);
			print_data (&nmc->nmc_config, out_indices, NULL, 0, &out);

			g_string_free (ac_paths_str, FALSE);
			was_output = TRUE;
		}
	}

	if (sections_array)
		g_array_free (sections_array, TRUE);
	if (fields_in_section)
		g_ptr_array_free (fields_in_section, TRUE);

	return TRUE;
}

void
nmc_device_state_to_color (NMDeviceState state, NMMetaTermColor *color, NMMetaTermFormat *color_fmt)
{
	*color = NM_META_TERM_COLOR_NORMAL;
	*color_fmt = NM_META_TERM_FORMAT_NORMAL;

	if (state <= NM_DEVICE_STATE_UNAVAILABLE)
		*color_fmt= NM_META_TERM_FORMAT_DIM;
	else if (state == NM_DEVICE_STATE_DISCONNECTED)
		*color = NM_META_TERM_COLOR_RED;
	else if (state >= NM_DEVICE_STATE_PREPARE && state <= NM_DEVICE_STATE_SECONDARIES)
		*color = NM_META_TERM_COLOR_YELLOW;
	else if (state == NM_DEVICE_STATE_ACTIVATED)
		*color = NM_META_TERM_COLOR_GREEN;
}

static void
fill_output_device_status (NMDevice *device, GPtrArray *output_data)
{
	NMActiveConnection *ac;
	NMDeviceState state;
	NMMetaTermColor color;
	NMMetaTermFormat color_fmt;
	NmcOutputField *arr = nmc_dup_fields_array ((const NMMetaAbstractInfo *const*) nmc_fields_dev_status,
	                                            0);

	state = nm_device_get_state (device);
	ac = nm_device_get_active_connection (device);

	/* Show devices in color */
	nmc_device_state_to_color (state, &color, &color_fmt);
	set_val_color_all (arr, color);
	set_val_color_fmt_all (arr, color_fmt);

	set_val_strc (arr, 0, nm_device_get_iface (device));
	set_val_strc (arr, 1, nm_device_get_type_description (device));
	set_val_strc (arr, 2, nmc_device_state_to_string (state));
	set_val_strc (arr, 3, nm_object_get_path (NM_OBJECT (device)));
	set_val_strc (arr, 4, get_active_connection_id (device));
	set_val_strc (arr, 5, ac ? nm_active_connection_get_uuid (ac) : NULL);
	set_val_strc (arr, 6, ac ? nm_object_get_path (NM_OBJECT (ac)) : NULL);

	g_ptr_array_add (output_data, arr);
}

static NMCResultCode
do_devices_status (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;
	NMDevice **devices;
	int i;
	const char *fields_str = NULL;
	const NMMetaAbstractInfo *const*tmpl;
	NmcOutputField *arr;
	NMC_OUTPUT_DATA_DEFINE_SCOPED (out);

	next_arg (nmc, &argc, &argv, NULL);

	/* Nothing to complete */
	if (nmc->complete)
		return nmc->return_value;

	while (argc > 0) {
		g_printerr (_("Unknown parameter: %s\n"), *argv);
		next_arg (nmc, &argc, &argv, NULL);
	}

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = NMC_FIELDS_DEV_STATUS_COMMON;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0) {
	} else
		fields_str = nmc->required_fields;

	tmpl = (const NMMetaAbstractInfo *const*) nmc_fields_dev_status;
	out_indices = parse_output_fields (fields_str, tmpl, FALSE, NULL, &error);

	if (error) {
		g_string_printf (nmc->return_text, _("Error: 'device status': %s"), error->message);
		g_error_free (error);
		return NMC_RESULT_ERROR_USER_INPUT;
	}

	/* Add headers */
	arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (out.output_data, arr);

	devices = nmc_get_devices_sorted (nmc->client);
	for (i = 0; devices[i]; i++)
		fill_output_device_status (devices[i], out.output_data);

	print_data_prepare_width (out.output_data);
	print_data (&nmc->nmc_config, out_indices, _("Status of devices"), 0, &out);

	g_free (devices);

	return NMC_RESULT_SUCCESS;
}

static NMCResultCode
do_device_show (NmCli *nmc, int argc, char **argv)
{
	gs_free_error GError *error = NULL;

	next_arg (nmc, &argc, &argv, NULL);
	if (!nmc->mode_specified)
		nmc->nmc_config_mutable.multiline_output = TRUE;  /* multiline mode is default for 'device show' */

	if (argc) {
		NMDevice *device;

		device = get_device (nmc, &argc, &argv, &error);
		if (!device) {
			g_string_printf (nmc->return_text, _("Error: %s."), error->message);
			return error->code;
		}

		if (argc) {
			g_string_printf (nmc->return_text, _("Error: invalid extra argument '%s'."), *argv);
			return NMC_RESULT_ERROR_USER_INPUT;
		}

		if (nmc->complete)
			return nmc->return_value;

		show_device_info (device, nmc);
	} else {
		NMDevice **devices = nmc_get_devices_sorted (nmc->client);
		int i;

		/* nmc_do_cmd() should not call this with argc=0. */
		g_assert (!nmc->complete);

		/* Show details for all devices */
		for (i = 0; devices[i]; i++) {
			if (!show_device_info (devices[i], nmc))
				break;
			if (devices[i + 1])
				g_print ("\n"); /* Empty line */
		}

		g_free (devices);
	}

	return nmc->return_value;
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
	NMDevice *device = (NMDevice *) user_data;

	nmc_terminal_show_progress (device ? nmc_device_state_to_string (nm_device_get_state (device)) : "");

	return TRUE;
}

static void connected_state_cb (NMDevice *device, NMActiveConnection *active);

static void
device_state_cb (NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
	NMActiveConnection *active = (NMActiveConnection *) user_data;

	connected_state_cb (device, active);
}

static void
active_state_cb (NMActiveConnection *active, GParamSpec *pspec, gpointer user_data)
{
	NMDevice *device = (NMDevice *) user_data;

	connected_state_cb (device, active);
}

static void
connected_state_cb (NMDevice *device, NMActiveConnection *active)
{
	NMDeviceState state;
	NMDeviceStateReason reason;
	NMActiveConnectionState ac_state;

	state = nm_device_get_state (device);
	ac_state = nm_active_connection_get_state (active);

	if (ac_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATING)
		return;

	if (state == NM_DEVICE_STATE_ACTIVATED) {
		nmc_terminal_erase_line ();
		g_print (_("Device '%s' successfully activated with '%s'.\n"),
		         nm_device_get_iface (device),
		         nm_active_connection_get_uuid (active));
	} else if (   state <= NM_DEVICE_STATE_DISCONNECTED
	           || state >= NM_DEVICE_STATE_DEACTIVATING) {
		reason = nm_device_get_state_reason (device);
		g_print (_("Error: Connection activation failed: (%d) %s.\n"),
		         reason, nmc_device_reason_to_string (reason));
	} else
		return;

	g_signal_handlers_disconnect_by_func (active, G_CALLBACK (active_state_cb), device);
	g_signal_handlers_disconnect_by_func (device, G_CALLBACK (device_state_cb), active);

	g_object_unref (active);
	g_object_unref (device);

	quit ();
}

typedef struct {
	NmCli *nmc;
	NMDevice *device;
	gboolean hotspot;
} AddAndActivateInfo;

static void
add_and_activate_cb (GObject *client,
                     GAsyncResult *result,
                     gpointer user_data)
{
	AddAndActivateInfo *info = (AddAndActivateInfo *) user_data;
	NmCli *nmc = info->nmc;
	NMDevice *device = info->device;
	NMActiveConnectionState state;
	NMActiveConnection *active;
	GError *error = NULL;

	active = nm_client_add_and_activate_connection_finish (NM_CLIENT (client), result, &error);

	if (error) {
		if (info->hotspot)
			g_string_printf (nmc->return_text, _("Error: Failed to setup a Wi-Fi hotspot: %s"),
			                 error->message);
		else
			g_string_printf (nmc->return_text, _("Error: Failed to add/activate new connection: %s"),
			                 error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		quit ();
	} else {
		state = nm_active_connection_get_state (active);

		if (state == NM_ACTIVE_CONNECTION_STATE_UNKNOWN) {
			if (info->hotspot)
				g_string_printf (nmc->return_text, _("Error: Failed to setup a Wi-Fi hotspot"));
			else
				g_string_printf (nmc->return_text, _("Error: Failed to add/activate new connection: Unknown error"));
			nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
			g_object_unref (active);
			quit ();
		}

		if (nmc->nowait_flag || state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
			/* User doesn't want to wait or already activated */
			if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
				if (nmc->nmc_config.print_output == NMC_PRINT_PRETTY)
					nmc_terminal_erase_line ();
				if (info->hotspot)
					g_print (_("Connection with UUID '%s' created and activated on device '%s'\n"),
					         nm_active_connection_get_uuid (active), nm_device_get_iface (device));
				else
					g_print (_("Hotspot '%s' activated on device '%s'\n"),
					         nm_active_connection_get_id (active), nm_device_get_iface (device));
			}
			g_object_unref (active);
			quit ();
		} else {
			g_object_ref (device);
			g_signal_connect (device, "notify::state", G_CALLBACK (device_state_cb), active);
			g_signal_connect (active, "notify::state", G_CALLBACK (active_state_cb), device);

			g_timeout_add_seconds (nmc->timeout, timeout_cb, nmc);  /* Exit if timeout expires */

			if (nmc->nmc_config.print_output == NMC_PRINT_PRETTY)
				progress_id = g_timeout_add (120, progress_cb, device);
		}
	}

	g_free (info);
}

static void
create_connect_connection_for_device (AddAndActivateInfo *info)
{
	NMConnection *connection;
	NMSettingConnection *s_con;

	/* Create new connection and tie it to the device */
	connection = nm_simple_connection_new ();
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, nm_device_get_iface (info->device),
	              NM_SETTING_CONNECTION_INTERFACE_NAME, nm_device_get_iface (info->device),
	              NULL);

	nm_client_add_and_activate_connection_async (info->nmc->client,
	                                             connection,
	                                             info->device,
	                                             NULL,
	                                             NULL,
	                                             add_and_activate_cb,
	                                             info);
}

static void
connect_device_cb (GObject *client, GAsyncResult *result, gpointer user_data)
{
	AddAndActivateInfo *info = (AddAndActivateInfo *) user_data;
	NmCli *nmc = info->nmc;
	NMActiveConnection *active;
	GError *error = NULL;
	const GPtrArray *devices;
	NMDevice *device;
	NMDeviceState state;

	active = nm_client_activate_connection_finish (NM_CLIENT (client), result, &error);

	if (error) {
		/* If no connection existed for the device, create one and activate it */
		if (g_error_matches (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_CONNECTION)) {
			create_connect_connection_for_device (info);
			return;
		}

		g_string_printf (nmc->return_text, _("Error: Device activation failed: %s"),
		                 error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		quit ();
	} else {
		g_assert (active);
		devices = nm_active_connection_get_devices (active);
		if (devices->len == 0) {
			g_string_printf (nmc->return_text, _("Error: Device activation failed: device was disconnected"));
			nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
			g_object_unref (active);
			quit ();
			g_free (info);
			return;
		}

		device = g_ptr_array_index (devices, 0);
		state = nm_device_get_state (device);

		if (nmc->nowait_flag || state == NM_DEVICE_STATE_ACTIVATED) {
			/* Don't want to wait or device already activated */
			if (state == NM_DEVICE_STATE_ACTIVATED && nmc->nmc_config.print_output == NMC_PRINT_PRETTY) {
				nmc_terminal_erase_line ();
				g_print (_("Device '%s' has been connected.\n"), nm_device_get_iface (device));
			}
			g_object_unref (active);
			quit ();
		} else {
			if (nmc->secret_agent) {
				NMRemoteConnection *connection = nm_active_connection_get_connection (active);

				nm_secret_agent_simple_enable (NM_SECRET_AGENT_SIMPLE (nmc->secret_agent),
				                               nm_connection_get_path (NM_CONNECTION (connection)));
			}

			g_object_ref (device);
			g_signal_connect (device, "notify::state", G_CALLBACK (device_state_cb), active);
			g_signal_connect (active, "notify::state", G_CALLBACK (active_state_cb), device);
			/* Start timer not to loop forever if "notify::state" signal is not issued */
			g_timeout_add_seconds (nmc->timeout, timeout_cb, nmc);
		}
	}
	g_free (info);
}

static NMCResultCode
do_device_connect (NmCli *nmc, int argc, char **argv)
{
	NMDevice *device = NULL;
	AddAndActivateInfo *info;
	gs_free_error GError *error = NULL;

	/* Set default timeout for connect operation. */
	if (nmc->timeout == -1)
		nmc->timeout = 90;

	next_arg (nmc, &argc, &argv, NULL);
	device = get_device (nmc, &argc, &argv, &error);
	if (!device) {
		g_string_printf (nmc->return_text, _("Error: %s."), error->message);
		return error->code;
	}

	if (*argv) {
		g_string_printf (nmc->return_text, _("Error: extra argument not allowed: '%s'."), *argv);
		return NMC_RESULT_ERROR_USER_INPUT;
	}

	if (nmc->complete)
		return nmc->return_value;

	/*
	 * Use nowait_flag instead of should_wait, because exiting has to be postponed
	 * till connect_device_cb() is called, giving NM time to check our permissions.
	 */
	nmc->nowait_flag = (nmc->timeout == 0);
	nmc->should_wait++;

	/* Create secret agent */
	nmc->secret_agent = nm_secret_agent_simple_new ("nmcli-connect");
	if (nmc->secret_agent) {
		g_signal_connect (nmc->secret_agent,
		                  NM_SECRET_AGENT_SIMPLE_REQUEST_SECRETS,
		                  G_CALLBACK (nmc_secrets_requested),
		                  nmc);
	}

	info = g_malloc0 (sizeof (AddAndActivateInfo));
	info->nmc = nmc;
	info->device = device;
	info->hotspot = FALSE;

	nm_client_activate_connection_async (nmc->client,
	                                     NULL,  /* let NM find a connection automatically */
	                                     device,
	                                     NULL,
	                                     NULL,
	                                     connect_device_cb,
	                                     info);

	/* Start progress indication */
	if (nmc->nmc_config.print_output == NMC_PRINT_PRETTY)
		progress_id = g_timeout_add (120, progress_cb, device);

	return nmc->return_value;
}

typedef struct {
	NmCli *nmc;
	GSList *queue;
	guint timeout_id;
	gboolean cmd_disconnect;
} DeviceCbInfo;

static void device_cb_info_finish (DeviceCbInfo *info, NMDevice *device);

static gboolean
device_op_timeout_cb (gpointer user_data)
{
	DeviceCbInfo *info = user_data;

	timeout_cb (info->nmc);
	device_cb_info_finish (info, NULL);
	return G_SOURCE_REMOVE;
}

static void
device_removed_cb (NMClient *client, NMDevice *device, DeviceCbInfo *info)
{
	/* Success: device has been removed.
	 * It can also happen when disconnecting a software device.
	 */
	if (!g_slist_find (info->queue, device))
		return;

	if (info->cmd_disconnect)
		g_print (_("Device '%s' successfully disconnected.\n"),
		         nm_device_get_iface (device));
	else
		g_print (_("Device '%s' successfully removed.\n"),
		         nm_device_get_iface (device));
	device_cb_info_finish (info, device);
}

static void
disconnect_state_cb (NMDevice *device, GParamSpec *pspec, DeviceCbInfo *info)
{
	if (!g_slist_find (info->queue, device))
		return;

	if (nm_device_get_state (device) <= NM_DEVICE_STATE_DISCONNECTED) {
		g_print (_("Device '%s' successfully disconnected.\n"),
		         nm_device_get_iface (device));
		device_cb_info_finish (info, device);
	}
}

static void
destroy_queue_element (gpointer data)
{
	g_signal_handlers_disconnect_matched (data, G_SIGNAL_MATCH_FUNC, 0, 0, 0,
	                                      disconnect_state_cb, NULL);
	g_object_unref (data);
}

static void
device_cb_info_finish (DeviceCbInfo *info, NMDevice *device)
{
	if (device) {
		GSList *elem = g_slist_find (info->queue, device);
		if (!elem)
			return;
		info->queue = g_slist_delete_link (info->queue, elem);
		destroy_queue_element (device);
	} else {
		g_slist_free_full (info->queue, destroy_queue_element);
		info->queue = NULL;
	}

	if (info->queue)
		return;

	if (info->timeout_id)
		g_source_remove (info->timeout_id);
	g_signal_handlers_disconnect_by_func (info->nmc->client, device_removed_cb, info);
	g_slice_free (DeviceCbInfo, info);
	quit ();
}

static void
reapply_device_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (object);
	DeviceCbInfo *info = (DeviceCbInfo *) user_data;
	NmCli *nmc = info->nmc;
	GError *error = NULL;

	if (!nm_device_reapply_finish (device, result, &error)) {
		g_string_printf (nmc->return_text, _("Error: Reapplying connection to device '%s' (%s) failed: %s"),
		                 nm_device_get_iface (device),
		                 nm_object_get_path (NM_OBJECT (device)),
		                 error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_DEV_DISCONNECT;
		device_cb_info_finish (info, device);
	} else {
		if (nmc->nmc_config.print_output == NMC_PRINT_PRETTY)
			nmc_terminal_erase_line ();
		g_print (_("Connection successfully reapplied to device '%s'.\n"),
		         nm_device_get_iface (device));
		device_cb_info_finish (info, device);
	}
}

static NMCResultCode
do_device_reapply (NmCli *nmc, int argc, char **argv)
{
	NMDevice *device;
	DeviceCbInfo *info = NULL;
	gs_free_error GError *error = NULL;

	/* Set default timeout for reapply operation. */
	if (nmc->timeout == -1)
		nmc->timeout = 10;

	next_arg (nmc, &argc, &argv, NULL);
	device = get_device (nmc, &argc, &argv, &error);
	if (!device) {
		g_string_printf (nmc->return_text, _("Error: %s."), error->message);
		return error->code;
	}

	if (argc) {
		g_string_printf (nmc->return_text, _("Error: invalid extra argument '%s'."), *argv);
		return NMC_RESULT_ERROR_USER_INPUT;
	}

	if (nmc->complete)
		return nmc->return_value;

	nmc->nowait_flag = (nmc->timeout == 0);
	nmc->should_wait++;

	info = g_slice_new0 (DeviceCbInfo);
	info->nmc = nmc;
	info->queue = g_slist_prepend (info->queue, g_object_ref (device));

	/* Now reapply the connection to the device */
	nm_device_reapply_async (device, NULL, 0, 0, NULL, reapply_device_cb, info);

	return nmc->return_value;
}

typedef struct {
	NmCli *nmc;
	int argc;
	char **argv;
} ModifyInfo;

static void
modify_reapply_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (object);
	ModifyInfo *info = user_data;
	NmCli *nmc = info->nmc;
	GError *error = NULL;

	if (!nm_device_reapply_finish (device, result, &error)) {
		g_string_printf (nmc->return_text, _("Error: Reapplying connection to device '%s' (%s) failed: %s"),
		                 nm_device_get_iface (device),
		                 nm_object_get_path (NM_OBJECT (device)),
		                 error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_DEV_DISCONNECT;
	} else {
		if (nmc->nmc_config.print_output == NMC_PRINT_PRETTY)
			nmc_terminal_erase_line ();
		g_print (_("Connection successfully reapplied to device '%s'.\n"),
		         nm_device_get_iface (device));
	}

	g_slice_free (ModifyInfo, info);
	quit ();
}

static void
modify_get_applied_cb (GObject *object,
                       GAsyncResult *result,
                       gpointer user_data)
{
	NMDevice *device = NM_DEVICE (object);
	ModifyInfo *info = user_data;
	NmCli *nmc = info->nmc;
	gs_free_error GError *error = NULL;
	NMConnection *connection;
	guint64 version_id;

	connection = nm_device_get_applied_connection_finish (device,
	                                                      result,
	                                                      &version_id,
	                                                      &error);
	if (!connection) {
		g_string_printf (nmc->return_text, _("Error: Reading applied connection from device '%s' (%s) failed: %s"),
		                 nm_device_get_iface (device),
		                 nm_object_get_path (NM_OBJECT (device)),
		                 error->message);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		g_slice_free (ModifyInfo, info);
		quit ();
		return;
	}

	if (!nmc_read_connection_properties (info->nmc, connection, &info->argc, &info->argv, &error)) {
		g_string_assign (nmc->return_text, error->message);
		nmc->return_value = error->code;
		g_slice_free (ModifyInfo, info);
		quit ();
		return;
	}

	if (nmc->complete)
		quit ();
	else
		nm_device_reapply_async (device, connection, version_id, 0, NULL, modify_reapply_cb, info);
}

static NMCResultCode
do_device_modify (NmCli *nmc, int argc, char **argv)
{
	NMDevice *device = NULL;
	ModifyInfo *info = NULL;
	gs_free_error GError *error = NULL;

	next_arg (nmc, &argc, &argv, NULL);
	device = get_device (nmc, &argc, &argv, &error);
	if (!device) {
		g_string_printf (nmc->return_text, _("Error: %s."), error->message);
		return error->code;
	}

	if (nmc->timeout == -1)
		nmc->timeout = 10;

	nmc->nowait_flag = (nmc->timeout == 0);
	nmc->should_wait++;

	info = g_slice_new0 (ModifyInfo);
	info->nmc = nmc;
	info->argc = argc;
	info->argv = argv;

	nm_device_get_applied_connection_async (device, 0, NULL, modify_get_applied_cb, info);

	return nmc->return_value;
}

static void
disconnect_device_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (object);
	DeviceCbInfo *info = (DeviceCbInfo *) user_data;
	NmCli *nmc = info->nmc;
	NMDeviceState state;
	GError *error = NULL;

	if (!nm_device_disconnect_finish (device, result, &error)) {
		g_string_printf (nmc->return_text, _("Error: not all devices disconnected."));
		g_printerr (_("Error: Device '%s' (%s) disconnecting failed: %s\n"),
		            nm_device_get_iface (device),
		            nm_object_get_path (NM_OBJECT (device)),
		            error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_DEV_DISCONNECT;
		device_cb_info_finish (info, device);
	} else {
		state = nm_device_get_state (device);
		if (nmc->nowait_flag || state <= NM_DEVICE_STATE_DISCONNECTED) {
			/* Don't want to wait or device already disconnected */
			if (state <= NM_DEVICE_STATE_DISCONNECTED) {
				if (nmc->nmc_config.print_output == NMC_PRINT_PRETTY)
					nmc_terminal_erase_line ();
				g_print (_("Device '%s' successfully disconnected.\n"),
				         nm_device_get_iface (device));
			}
			device_cb_info_finish (info, device);
		}
	}
}

static NMCResultCode
do_devices_disconnect (NmCli *nmc, int argc, char **argv)
{
	NMDevice *device;
	DeviceCbInfo *info = NULL;
	GSList *queue, *iter;

	/* Set default timeout for disconnect operation. */
	if (nmc->timeout == -1)
		nmc->timeout = 10;

	next_arg (nmc, &argc, &argv, NULL);
	queue = get_device_list (nmc, argc, argv);
	if (!queue)
		return nmc->return_value;
	if (nmc->complete)
		goto out;
	queue = g_slist_reverse (queue);

	info = g_slice_new0 (DeviceCbInfo);
	info->nmc = nmc;
	info->cmd_disconnect = TRUE;
	if (nmc->timeout > 0)
		info->timeout_id = g_timeout_add_seconds (nmc->timeout, device_op_timeout_cb, info);

	g_signal_connect (nmc->client, NM_CLIENT_DEVICE_REMOVED,
	                  G_CALLBACK (device_removed_cb), info);

	nmc->nowait_flag = (nmc->timeout == 0);
	nmc->should_wait++;

	for (iter = queue; iter; iter = g_slist_next (iter)) {
		device = iter->data;

		info->queue = g_slist_prepend (info->queue, g_object_ref (device));
		g_signal_connect (device, "notify::" NM_DEVICE_STATE,
		                  G_CALLBACK (disconnect_state_cb), info);

		/* Now disconnect the device */
		nm_device_disconnect_async (device, NULL, disconnect_device_cb, info);
	}

out:
	g_slist_free (queue);
	return nmc->return_value;
}

static void
delete_device_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (object);
	DeviceCbInfo *info = (DeviceCbInfo *) user_data;
	NmCli *nmc = info->nmc;
	GError *error = NULL;

	if (!nm_device_delete_finish (device, result, &error)) {
		g_string_printf (nmc->return_text, _("Error: not all devices deleted."));
		g_printerr (_("Error: Device '%s' (%s) deletion failed: %s\n"),
		            nm_device_get_iface (device),
		            nm_object_get_path (NM_OBJECT (device)),
		            error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		device_cb_info_finish (info, device);
	} else {
		if (nmc->nowait_flag)
			device_cb_info_finish (info, device);
	}
}

static NMCResultCode
do_devices_delete (NmCli *nmc, int argc, char **argv)
{
	NMDevice *device;
	DeviceCbInfo *info = NULL;
	GSList *queue, *iter;

	/* Set default timeout for delete operation. */
	if (nmc->timeout == -1)
		nmc->timeout = 10;

	next_arg (nmc, &argc, &argv, NULL);
	queue = get_device_list (nmc, argc, argv);
	if (!queue)
		return nmc->return_value;
	if (nmc->complete)
		goto out;
	queue = g_slist_reverse (queue);

	info = g_slice_new0 (DeviceCbInfo);
	info->nmc = nmc;
	if (nmc->timeout > 0)
		info->timeout_id = g_timeout_add_seconds (nmc->timeout, device_op_timeout_cb, info);

	g_signal_connect (nmc->client, NM_CLIENT_DEVICE_REMOVED,
	                  G_CALLBACK (device_removed_cb), info);

	nmc->nowait_flag = (nmc->timeout == 0);
	nmc->should_wait++;

	for (iter = queue; iter; iter = g_slist_next (iter)) {
		device = iter->data;

		info->queue = g_slist_prepend (info->queue, g_object_ref (device));

		/* Now delete the device */
		nm_device_delete_async (device, NULL, delete_device_cb, info);
	}

out:
	g_slist_free (queue);
	return nmc->return_value;
}

static NMCResultCode
do_device_set (NmCli *nmc, int argc, char **argv)
{
#define DEV_SET_AUTOCONNECT 0
#define DEV_SET_MANAGED     1
	NMDevice *device = NULL;
	int i;
	struct {
		int idx;
		gboolean value;
	} values[2] = {
		[DEV_SET_AUTOCONNECT] = { -1 },
		[DEV_SET_MANAGED]     = { -1 },
	};
	gs_free_error GError *error = NULL;

	next_arg (nmc, &argc, &argv, NULL);
	if (argc >= 1 && g_strcmp0 (*argv, "ifname") == 0)
		next_arg (nmc, &argc, &argv, NULL);

	device = get_device (nmc, &argc, &argv, &error);
	if (!device) {
		g_string_printf (nmc->return_text, _("Error: %s."), error->message);
		return error->code;
	}

        if (!argc) {
		g_string_printf (nmc->return_text, _("Error: No property specified."));
		return NMC_RESULT_ERROR_USER_INPUT;
	}

	i = 0;
	do {
		gboolean flag;

		if (argc == 1 && nmc->complete)
			nmc_complete_strings (*argv, "managed", "autoconnect", NULL);

		if (matches (*argv, "managed")) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: '%s' argument is missing."), *(argv-1));
				return NMC_RESULT_ERROR_USER_INPUT;
			}
			if (argc == 1 && nmc->complete)
				nmc_complete_bool (*argv);
			if (!nmc_string_to_bool (*argv, &flag, &error)) {
				g_string_printf (nmc->return_text, _("Error: 'managed': %s."),
				                 error->message);
				return NMC_RESULT_ERROR_USER_INPUT;
			}
			values[DEV_SET_MANAGED].idx = ++i;
			values[DEV_SET_MANAGED].value = flag;
		}
		else if (matches (*argv, "autoconnect")) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: '%s' argument is missing."), *(argv-1));
				return NMC_RESULT_ERROR_USER_INPUT;
			}
			if (argc == 1 && nmc->complete)
				nmc_complete_bool (*argv);
			if (!nmc_string_to_bool (*argv, &flag, &error)) {
				g_string_printf (nmc->return_text, _("Error: 'autoconnect': %s."),
				                 error->message);
				return NMC_RESULT_ERROR_USER_INPUT;
			}
			values[DEV_SET_AUTOCONNECT].idx = ++i;
			values[DEV_SET_AUTOCONNECT].value = flag;
		}
		else {
			g_string_printf (nmc->return_text, _("Error: property '%s' is not known."), *argv);
			return NMC_RESULT_ERROR_USER_INPUT;
		}
	} while (next_arg (nmc, &argc, &argv, NULL) == 0);

	if (nmc->complete)
		return nmc->return_value;

	/* when multiple properties are specified, set them in the order as they
	 * are specified on the command line. */
	if (   values[DEV_SET_AUTOCONNECT].idx >= 0
	    && values[DEV_SET_MANAGED].idx >= 0
	    && values[DEV_SET_MANAGED].idx < values[DEV_SET_AUTOCONNECT].idx) {
		nm_device_set_managed (device, values[DEV_SET_MANAGED].value);
		values[DEV_SET_MANAGED].idx = -1;
	}
	if (values[DEV_SET_AUTOCONNECT].idx >= 0)
		nm_device_set_autoconnect (device, values[DEV_SET_AUTOCONNECT].value);
	if (values[DEV_SET_MANAGED].idx >= 0)
		nm_device_set_managed (device, values[DEV_SET_MANAGED].value);

	return nmc->return_value;
}

static void
device_state (NMDevice *device, GParamSpec *pspec, NmCli *nmc)
{
	NMDeviceState state = nm_device_get_state (device);
	NMMetaTermColor color;
	NMMetaTermFormat color_fmt;
	char *str;

	nmc_device_state_to_color (state, &color, &color_fmt);
	str = nmc_colorize (nmc->nmc_config.use_colors, color, color_fmt, "%s: %s\n",
	                    nm_device_get_iface (device),
	                    nmc_device_state_to_string (state));

	g_print ("%s", str);
	g_free (str);
}

static void
device_ac (NMDevice *device, GParamSpec *pspec, NmCli *nmc)
{
	NMActiveConnection *ac = nm_device_get_active_connection (device);
	const char *id = ac ? nm_active_connection_get_id (ac) : NULL;

	if (!id)
		return;

	g_print (_("%s: using connection '%s'\n"), nm_device_get_iface (device), id);
}

static void
device_watch (NmCli *nmc, NMDevice *device)
{
	nmc->should_wait++;
	g_signal_connect (device, "notify::" NM_DEVICE_STATE, G_CALLBACK (device_state), nmc);
	g_signal_connect (device, "notify::" NM_DEVICE_ACTIVE_CONNECTION, G_CALLBACK (device_ac), nmc);
}

static void
device_unwatch (NmCli *nmc, NMDevice *device)
{
	g_signal_handlers_disconnect_by_func (device, device_state, nmc);
	if (g_signal_handlers_disconnect_by_func (device, device_ac, nmc))
		nmc->should_wait--;

	/* Terminate if all the watched devices disappeared. */
	if (!nmc->should_wait)
		quit ();
}

static void
device_added (NMClient *client, NMDevice *device, NmCli *nmc)
{
	g_print (_("%s: device created\n"), nm_device_get_iface (device));
	device_watch (nmc, NM_DEVICE (device));
}

static void
device_removed (NMClient *client, NMDevice *device, NmCli *nmc)
{
	g_print (_("%s: device removed\n"), nm_device_get_iface (device));
	device_unwatch (nmc, device);
}

static NMCResultCode
do_devices_monitor (NmCli *nmc, int argc, char **argv)
{
	if (nmc->complete)
		return nmc->return_value;

	next_arg (nmc, &argc, &argv, NULL);
	if (argc == 0) {
		/* No devices specified. Monitor all. */
		const GPtrArray *devices = nm_client_get_devices (nmc->client);
		int i;

		for (i = 0; i < devices->len; i++)
			device_watch (nmc, g_ptr_array_index (devices, i));

		/* We'll watch the device additions too, never exit. */
		nmc->should_wait++;
		g_signal_connect (nmc->client, NM_CLIENT_DEVICE_ADDED, G_CALLBACK (device_added), nmc);
	} else {
		GSList *queue = get_device_list (nmc, argc, argv);
		GSList *iter;

		/* Monitor the specified devices. */
		for (iter = queue; iter; iter = g_slist_next (iter))
			device_watch (nmc, NM_DEVICE (iter->data));
		g_slist_free (queue);
	}

	g_signal_connect (nmc->client, NM_CLIENT_DEVICE_REMOVED, G_CALLBACK (device_removed), nmc);
	return nmc->return_value;
}

static void
show_access_point_info (NMDevice *device, NmCli *nmc, NmcOutputData *out)
{
	NMAccessPoint *active_ap = NULL;
	const char *active_bssid = NULL;
	GPtrArray *aps;
	NmcOutputField *arr;

	if (nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED) {
		active_ap = nm_device_wifi_get_active_access_point (NM_DEVICE_WIFI (device));
		active_bssid = active_ap ? nm_access_point_get_bssid (active_ap) : NULL;
	}

	arr = nmc_dup_fields_array ((const NMMetaAbstractInfo *const*) nmc_fields_dev_wifi_list,
	                            NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (out->output_data, arr);

	{
		APInfo info = {
			.nmc = nmc,
			.index = 1,
			.output_flags = 0,
			.active_bssid = active_bssid,
			.device = nm_device_get_iface (device),
			.output_data = out->output_data,
		};

		aps = sort_access_points (nm_device_wifi_get_access_points (NM_DEVICE_WIFI (device)));
		g_ptr_array_foreach (aps, fill_output_access_point, &info);
		g_ptr_array_free (aps, FALSE);
	}

	print_data_prepare_width (out->output_data);
}

/*
 * Find a Wi-Fi device with 'iface' in 'devices' array. If 'iface' is NULL,
 * the first Wi-Fi device is returned. 'idx' parameter is updated to the point
 * where the function finished so that the function can be called repeatedly
 * to get next matching device.
 * Returns: found device or NULL
 */
static NMDevice *
find_wifi_device_by_iface (NMDevice **devices, const char *iface, int *idx)
{
	int i;

	for (i = idx ? *idx : 0; devices[i]; i++) {
		const char *dev_iface = nm_device_get_iface (devices[i]);

		if (!NM_IS_DEVICE_WIFI (devices[i]))
			continue;

		if (iface) {
			/* If a iface was specified then use it. */
			if (g_strcmp0 (dev_iface, iface) == 0)
				break;
		} else {
			/* Else return the first Wi-Fi device. */
			break;
		}
	}

	if (idx)
		*idx = i + 1;
	return devices[i];
}

/*
 * Find AP on 'device' according to 'bssid' or 'ssid' parameter.
 * Returns: found AP or NULL
 */
static NMAccessPoint *
find_ap_on_device (NMDevice *device, const char *bssid, const char *ssid, gboolean complete)
{
	const GPtrArray *aps;
	NMAccessPoint *ap = NULL;
	int i;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), NULL);

	aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (device));
	for (i = 0; i < aps->len; i++) {
		NMAccessPoint *candidate_ap = g_ptr_array_index (aps, i);

		if (bssid) {
			/* Parameter is BSSID */
			const char *candidate_bssid = nm_access_point_get_bssid (candidate_ap);

			/* Compare BSSIDs */
			if (complete) {
				if (g_str_has_prefix (candidate_bssid, bssid))
					g_print ("%s\n", candidate_bssid);
			} else if (strcmp (bssid, candidate_bssid) == 0) {
				ap = candidate_ap;
				break;
			}
		}

		if (ssid) {
			/* Parameter is SSID */
			GBytes *candidate_ssid;
			char *ssid_tmp;

			candidate_ssid = nm_access_point_get_ssid (candidate_ap);
			if (!candidate_ssid)
				continue;

			ssid_tmp = nm_utils_ssid_to_utf8 (g_bytes_get_data (candidate_ssid, NULL),
			                                  g_bytes_get_size (candidate_ssid));

			/* Compare SSIDs */
			if (complete) {
				if (g_str_has_prefix (ssid_tmp, ssid))
					g_print ("%s\n", ssid_tmp);
			} else if (strcmp (ssid, ssid_tmp) == 0) {
				ap = candidate_ap;
				g_free (ssid_tmp);
				break;
			}
			g_free (ssid_tmp);
		}
	}

	return ap;
}

static void
complete_aps (NMDevice **devices, const char *ifname,
              const char *bssid_prefix, const char *ssid_prefix)
{
	int devices_idx = 0;
	NMDevice *device;

	while ((device = find_wifi_device_by_iface (devices, ifname, &devices_idx)))
		find_ap_on_device (device, bssid_prefix, ssid_prefix, TRUE);
}

void
nmc_complete_bssid (NMClient *client, const char *ifname, const char *bssid_prefix)
{
	gs_free NMDevice **devices = NULL;

	devices = nmc_get_devices_sorted (client);
	complete_aps (devices, ifname, bssid_prefix, NULL);
}

static NMCResultCode
do_device_wifi_list (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;
	NMDevice *device = NULL;
	NMAccessPoint *ap = NULL;
	const char *ifname = NULL;
	const char *bssid_user = NULL;
	gs_free NMDevice **devices = NULL;
	const GPtrArray *aps;
	APInfo *info;
	int i, j;
	const char *fields_str = NULL;
	const NMMetaAbstractInfo *const*tmpl;
	NmcOutputField *arr;
	const char *base_hdr = _("Wi-Fi scan list");
	NMC_OUTPUT_DATA_DEFINE_SCOPED (out);
	gs_free char *header_name = NULL;

	devices = nmc_get_devices_sorted (nmc->client);

	next_arg (nmc, &argc, &argv, NULL);
	while (argc > 0) {
		if (argc == 1 && nmc->complete)
			nmc_complete_strings (*argv, "ifname", "bssid", NULL);

		if (strcmp (*argv, "ifname") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				return NMC_RESULT_ERROR_USER_INPUT;
			}
			ifname = *argv;
			if (argc == 1 && nmc->complete)
				complete_device (devices, ifname, TRUE);
		} else if (strcmp (*argv, "bssid") == 0 || strcmp (*argv, "hwaddr") == 0) {
			/* hwaddr is deprecated and will be removed later */
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				return NMC_RESULT_ERROR_USER_INPUT;
			}
			bssid_user = *argv;
			if (argc == 1 && nmc->complete)
				complete_aps (devices, NULL, bssid_user, NULL);
		} else if (!nmc->complete) {
			g_printerr (_("Unknown parameter: %s\n"), *argv);
		}

		next_arg (nmc, &argc, &argv, NULL);
	}

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = NMC_FIELDS_DEV_WIFI_LIST_COMMON;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0) {
	} else
		fields_str = nmc->required_fields;

	tmpl = (const NMMetaAbstractInfo *const*) nmc_fields_dev_wifi_list;
	out_indices = parse_output_fields (fields_str, tmpl, FALSE, NULL, &error);

	if (error) {
		g_string_printf (nmc->return_text, _("Error: 'device wifi': %s"), error->message);
		g_error_free (error);
		return NMC_RESULT_ERROR_USER_INPUT;
	}

	if (nmc->complete)
		return nmc->return_value;

	if (ifname) {

		device = find_wifi_device_by_iface (devices, ifname, NULL);
		if (!device) {
			g_string_printf (nmc->return_text, _("Error: Device '%s' not found."), ifname);
			return NMC_RESULT_ERROR_NOT_FOUND;
		}
		/* Main header name */
		header_name = construct_header_name (base_hdr, ifname);

		if (NM_IS_DEVICE_WIFI (device)) {
			if (bssid_user) {
				/* Specific AP requested - list only that */
				aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (device));
				for (j = 0; j < aps->len; j++) {
					char *bssid_up;
					NMAccessPoint *candidate_ap = g_ptr_array_index (aps, j);
					const char *candidate_bssid = nm_access_point_get_bssid (candidate_ap);

					bssid_up = g_ascii_strup (bssid_user, -1);
					if (!strcmp (bssid_up, candidate_bssid))
						ap = candidate_ap;
					g_free (bssid_up);
				}
				if (!ap) {
					g_string_printf (nmc->return_text, _("Error: Access point with bssid '%s' not found."),
					                 bssid_user);
					return NMC_RESULT_ERROR_NOT_FOUND;
				}
				/* Add headers (field names) */
				arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (out.output_data, arr);

				info = g_malloc0 (sizeof (APInfo));
				info->nmc = nmc;
				info->index = 1;
				info->output_flags = 0;
				info->active_bssid = NULL;
				info->device = nm_device_get_iface (device);

				fill_output_access_point (ap, info);

				print_data_prepare_width (out.output_data);
				print_data (&nmc->nmc_config, out_indices, header_name, 0, &out);
				g_free (info);
			} else {
				show_access_point_info (device, nmc, &out);
				print_data (&nmc->nmc_config, out_indices, NULL, 0, &out);
			}
		} else {
			if (   nm_device_get_device_type (device) == NM_DEVICE_TYPE_GENERIC
			    && g_strcmp0 (nm_device_get_type_description (device), "wifi") == 0) {
				g_string_printf (nmc->return_text,
				                 _("Error: Device '%s' was not recognized as a Wi-Fi device, check NetworkManager Wi-Fi plugin."),
				                 ifname);
			} else {
				g_string_printf (nmc->return_text,
				                 _("Error: Device '%s' is not a Wi-Fi device."),
				                 ifname);
			}
			return NMC_RESULT_ERROR_UNKNOWN;
		}
	} else {
		gboolean empty_line = FALSE;

		/* List APs for all devices */
		if (bssid_user) {
			/* Specific AP requested - list only that */
			for (i = 0; devices[i]; i++) {
				NMDevice *dev = devices[i];
				NMC_OUTPUT_DATA_DEFINE_SCOPED (out2);
				gs_free char *header_name2 = NULL;

				if (!NM_IS_DEVICE_WIFI (dev))
					continue;

				/* Main header name */
				header_name2 = construct_header_name (base_hdr, nm_device_get_iface (dev));
				out2_indices = parse_output_fields (fields_str, tmpl, FALSE, NULL, NULL);

				arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (out2.output_data, arr);

				aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (dev));
				for (j = 0; j < aps->len; j++) {
					char *bssid_up;
					NMAccessPoint *candidate_ap = g_ptr_array_index (aps, j);
					const char *candidate_bssid = nm_access_point_get_bssid (candidate_ap);

					bssid_up = g_ascii_strup (bssid_user, -1);
					if (!strcmp (bssid_up, candidate_bssid)) {
						ap = candidate_ap;

						info = g_malloc0 (sizeof (APInfo));
						info->nmc = nmc;
						info->index = 1;
						info->output_flags = 0;
						info->active_bssid = NULL;
						info->device = nm_device_get_iface (dev);
						fill_output_access_point (ap, info);
						g_free (info);
					}
					g_free (bssid_up);
				}
				if (empty_line)
					g_print ("\n"); /* Empty line between devices' APs */
				print_data_prepare_width (out2.output_data);
				print_data (&nmc->nmc_config, out2_indices, header_name2, 0, &out2);
				empty_line = TRUE;
			}
			if (!ap) {
				g_string_printf (nmc->return_text, _("Error: Access point with bssid '%s' not found."),
				                 bssid_user);
				return NMC_RESULT_ERROR_NOT_FOUND;
			}
		} else {
			for (i = 0; devices[i]; i++) {
				NMDevice *dev = devices[i];
				NMC_OUTPUT_DATA_DEFINE_SCOPED (out2);
				gs_free char *header_name2 = NULL;

				/* Main header name */
				header_name2 = construct_header_name (base_hdr,
				                                      nm_device_get_iface (dev));
				out2_indices = parse_output_fields (fields_str, tmpl, FALSE, NULL, NULL);

				if (NM_IS_DEVICE_WIFI (dev)) {
					if (empty_line)
						g_print ("\n"); /* Empty line between devices' APs */
					show_access_point_info (dev, nmc, &out2);
					print_data (&nmc->nmc_config, out2_indices, header_name2, 0, &out2);
					empty_line = TRUE;
				}
			}
		}
	}

	return nmc->return_value;
}

static NMCResultCode
do_device_wifi_connect_network (NmCli *nmc, int argc, char **argv)
{
	NMDevice *device = NULL;
	NMAccessPoint *ap = NULL;
	NM80211ApFlags ap_flags = NM_802_11_AP_FLAGS_NONE;
	NM80211ApSecurityFlags ap_wpa_flags = NM_802_11_AP_SEC_NONE;
	NM80211ApSecurityFlags ap_rsn_flags = NM_802_11_AP_SEC_NONE;
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	AddAndActivateInfo *info;
	const char *param_user = NULL;
	const char *ifname = NULL;
	const char *bssid = NULL;
	const char *password = NULL;
	const char *con_name = NULL;
	gboolean private = FALSE;
	gboolean hidden = FALSE;
	gboolean wep_passphrase = FALSE;
	GByteArray *bssid1_arr = NULL;
	GByteArray *bssid2_arr = NULL;
	gs_free NMDevice **devices = NULL;
	int devices_idx;
	char *ssid_ask = NULL;
	char *passwd_ask = NULL;

	/* Set default timeout waiting for operation completion. */
	if (nmc->timeout == -1)
		nmc->timeout = 90;

	devices = nmc_get_devices_sorted (nmc->client);

	next_arg (nmc, &argc, &argv, NULL);
	/* Get the first compulsory argument (SSID or BSSID) */
	if (argc > 0) {
		param_user = *argv;
		bssid1_arr = nm_utils_hwaddr_atoba (param_user, ETH_ALEN);

		if (argc == 1 && nmc->complete)
			complete_aps (devices, NULL, param_user, param_user);

		next_arg (nmc, &argc, &argv, NULL);
	} else {
		/* nmc_do_cmd() should not call this with argc=0. */
		g_assert (!nmc->complete);

		if (nmc->ask) {
			ssid_ask = nmc_readline (_("SSID or BSSID: "));
			param_user = ssid_ask ? ssid_ask : "";
			bssid1_arr = nm_utils_hwaddr_atoba (param_user, ETH_ALEN);
		}
		if (!ssid_ask) {
			g_string_printf (nmc->return_text, _("Error: SSID or BSSID are missing."));
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto finish;
		}
	}

	/* Get the rest of the parameters */
	while (argc > 0) {
		if (argc == 1 && nmc->complete) {
			nmc_complete_strings (*argv, "ifname", "bssid", "password", "wep-key-type",
			                      "name", "private", "hidden", NULL);
		}

		if (strcmp (*argv, "ifname") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
			ifname = *argv;
			if (argc == 1 && nmc->complete)
				complete_device (devices, ifname, TRUE);
		} else if (strcmp (*argv, "bssid") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
			bssid = *argv;
			if (argc == 1 && nmc->complete)
				complete_aps (devices, NULL, bssid, NULL);
			bssid2_arr = nm_utils_hwaddr_atoba (bssid, ETH_ALEN);
			if (!bssid2_arr) {
				g_string_printf (nmc->return_text, _("Error: bssid argument value '%s' is not a valid BSSID."),
				                 bssid);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
		} else if (strcmp (*argv, "password") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
			password = *argv;
		} else if (strcmp (*argv, "wep-key-type") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
			if (argc == 1 && nmc->complete)
				nmc_complete_strings (*argv, "key", "phrase", NULL);
			if (strcmp (*argv, "key") == 0)
				wep_passphrase = FALSE;
			else if (strcmp (*argv, "phrase") == 0)
				wep_passphrase = TRUE;
			else {
				g_string_printf (nmc->return_text,
				                 _("Error: wep-key-type argument value '%s' is invalid, use 'key' or 'phrase'."),
				                 *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
		} else if (strcmp (*argv, "name") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
			con_name = *argv;
		} else if (strcmp (*argv, "private") == 0) {
			GError *err_tmp = NULL;

			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
			if (argc == 1 && nmc->complete)
				nmc_complete_bool (*argv);
			if (!nmc_string_to_bool (*argv, &private, &err_tmp)) {
				g_string_printf (nmc->return_text, _("Error: %s: %s."), *(argv-1), err_tmp->message);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				g_clear_error (&err_tmp);
				goto finish;
			}
		} else if (strcmp (*argv, "hidden") == 0) {
			GError *err_tmp = NULL;

			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
			if (argc == 1 && nmc->complete)
				nmc_complete_bool (*argv);
			if (!nmc_string_to_bool (*argv, &hidden, &err_tmp)) {
				g_string_printf (nmc->return_text, _("Error: %s: %s."), *(argv-1), err_tmp->message);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				g_clear_error (&err_tmp);
				goto finish;
			}
		} else if (!nmc->complete) {
			g_printerr (_("Unknown parameter: %s\n"), *argv);
		}

		next_arg (nmc, &argc, &argv, NULL);
	}

	if (nmc->complete)
		goto finish;

	/* Verify SSID/BSSID parameters */
	if (bssid1_arr && bssid2_arr && memcmp (bssid1_arr->data, bssid2_arr->data, ETH_ALEN)) {
		g_string_printf (nmc->return_text, _("Error: BSSID to connect to (%s) differs from bssid argument (%s)."),
		                 param_user, bssid);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}
	if (!bssid1_arr && strlen (param_user) > 32) {
		g_string_printf (nmc->return_text, _("Error: Parameter '%s' is neither SSID nor BSSID."), param_user);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto finish;
	}

	/* Find a device to activate the connection on */
	devices_idx = 0;
	device = find_wifi_device_by_iface (devices, ifname, &devices_idx);

	if (!device) {
		if (ifname)
			g_string_printf (nmc->return_text, _("Error: Device '%s' is not a Wi-Fi device."), ifname);
		else
			g_string_printf (nmc->return_text, _("Error: No Wi-Fi device found."));
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto finish;
	}

	/* For hidden SSID first scan it so that NM learns about the AP */
	if (hidden) {
		GVariantBuilder builder, array_builder;
		GVariant *options;
		GError *scan_err = NULL;

		g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
		g_variant_builder_init (&array_builder, G_VARIANT_TYPE ("aay"));
		g_variant_builder_add (&array_builder, "@ay",
		                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, param_user, strlen (param_user), 1));
		g_variant_builder_add (&builder, "{sv}", "ssids", g_variant_builder_end (&array_builder));
		options = g_variant_builder_end (&builder);

		nm_device_wifi_request_scan_options (NM_DEVICE_WIFI (device), options, NULL, &scan_err);
		if (scan_err) {
			g_string_printf (nmc->return_text, _("Error: Failed to scan hidden SSID: %s."),
			                 scan_err->message);
			g_clear_error (&scan_err);
			nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
			goto finish;
		}
	}

	/* Find an AP to connect to */
	ap = find_ap_on_device (device, bssid1_arr ? param_user : NULL,
	                                bssid1_arr ? NULL : param_user, FALSE);
	if (!ap && !ifname) {
		NMDevice *dev;

		/* AP not found, ifname was not specified, so try finding the AP on another device. */
		while ((dev = find_wifi_device_by_iface (devices, NULL, &devices_idx)) != NULL) {
			ap = find_ap_on_device (dev, bssid1_arr ? param_user : NULL,
			                             bssid1_arr ? NULL : param_user, FALSE);
			if (ap) {
				device = dev;
				break;
			}
		}
	}

	if (!ap) {
		if (!bssid1_arr)
			g_string_printf (nmc->return_text, _("Error: No network with SSID '%s' found."), param_user);
		else
			g_string_printf (nmc->return_text, _("Error: No access point with BSSID '%s' found."), param_user);
		nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
		goto finish;
	}

	/* If there are some connection data from user, create a connection and
	 * fill them into proper settings. */
	if (con_name || private || bssid2_arr || password || hidden)
		connection = nm_simple_connection_new ();

	if (con_name || private) {
		s_con =  (NMSettingConnection *) nm_setting_connection_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_con));

		/* Set user provided connection name */
		if (con_name)
			g_object_set (s_con, NM_SETTING_CONNECTION_ID, con_name, NULL);

		/* Connection will only be visible to this user when 'private' is specified */
		if (private)
			nm_setting_connection_add_permission (s_con, "user", g_get_user_name (), NULL);
	}
	if (bssid2_arr || hidden) {
		s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wifi));

		/* 'bssid' parameter is used to restrict the connection only to the BSSID */
		if (bssid2_arr)
			g_object_set (s_wifi, NM_SETTING_WIRELESS_BSSID, bssid2_arr, NULL);

		/* 'hidden' parameter is used to indicate that SSID is not broadcasted */
		if (hidden) {
			GBytes *ssid = g_bytes_new (param_user, strlen (param_user));

			g_object_set (s_wifi,
			              NM_SETTING_WIRELESS_SSID, ssid,
			              NM_SETTING_WIRELESS_HIDDEN, hidden,
			              NULL);
			g_bytes_unref (ssid);

			/* Warn when the provided AP identifier looks like BSSID instead of SSID */
			if (bssid1_arr)
				g_printerr (_("Warning: '%s' should be SSID for hidden APs; but it looks like a BSSID.\n"),
				               param_user);
		}
	}

	/* handle password */
	ap_flags = nm_access_point_get_flags (ap);
	ap_wpa_flags = nm_access_point_get_wpa_flags (ap);
	ap_rsn_flags = nm_access_point_get_rsn_flags (ap);

	/* Set password for WEP or WPA-PSK. */
	if (ap_flags & NM_802_11_AP_FLAGS_PRIVACY) {
		/* Ask for missing password when one is expected and '--ask' is used */
		if (!password && nmc->ask)
			password = passwd_ask = nmc_readline_echo (nmc->nmc_config.show_secrets, _("Password: "));

		if (password) {
			if (!connection)
				connection = nm_simple_connection_new ();
			s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
			nm_connection_add_setting (connection, NM_SETTING (s_wsec));

			if (ap_wpa_flags == NM_802_11_AP_SEC_NONE && ap_rsn_flags == NM_802_11_AP_SEC_NONE) {
				/* WEP */
				nm_setting_wireless_security_set_wep_key (s_wsec, 0, password);
				g_object_set (G_OBJECT (s_wsec),
				              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE,
				              wep_passphrase ? NM_WEP_KEY_TYPE_PASSPHRASE: NM_WEP_KEY_TYPE_KEY,
				              NULL);
			} else if (   (ap_wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)
			           || (ap_rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)) {
				/* WPA PSK */
				g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_PSK, password, NULL);
			}
		}
	}
	// FIXME: WPA-Enterprise is not supported yet.
	// We are not able to determine and fill all the parameters for
	// 802.1X authentication automatically without user providing
	// the data. Adding nmcli options for the 8021x setting would
	// clutter the command. However, that could be solved later by
	// implementing add/edit connections support for nmcli.

	/* nowait_flag indicates user input. should_wait says whether quit in start().
	 * We have to delay exit after add_and_activate_cb() is called, even if
	 * the user doesn't want to wait, in order to give NM time to check our
	 * permissions. */
	nmc->nowait_flag = (nmc->timeout == 0);
	nmc->should_wait++;

	info = g_malloc0 (sizeof (AddAndActivateInfo));
	info->nmc = nmc;
	info->device = device;
	info->hotspot = FALSE;

	nm_client_add_and_activate_connection_async (nmc->client,
	                                             connection,
	                                             device,
	                                             nm_object_get_path (NM_OBJECT (ap)),
	                                             NULL,
	                                             add_and_activate_cb,
	                                             info);

finish:
	if (bssid1_arr)
		g_byte_array_free (bssid1_arr, TRUE);
	if (bssid2_arr)
		g_byte_array_free (bssid2_arr, TRUE);
	g_free (ssid_ask);
	g_free (passwd_ask);

	return nmc->return_value;
}

static GBytes *
generate_ssid_for_hotspot (const char *ssid)
{
	GBytes *ssid_bytes;
	char *hotspot_ssid = NULL;

	if (!ssid) {
		hotspot_ssid = g_strdup_printf ("Hotspot-%s", g_get_host_name ());
		if (strlen (hotspot_ssid) > 32)
			hotspot_ssid[32] = '\0';
		ssid = hotspot_ssid;
	}
	ssid_bytes = g_bytes_new (ssid, strlen (ssid));
	g_free (hotspot_ssid);
	return ssid_bytes;
}

#define WPA_PASSKEY_SIZE 8
static void
generate_wpa_key (char *key, size_t len)
{
	guint i;

	g_return_if_fail (key);
	g_return_if_fail (len > WPA_PASSKEY_SIZE);

	/* generate a 8-chars ASCII WPA key */
	for (i = 0; i < WPA_PASSKEY_SIZE; i++) {
		int c;
		c = g_random_int_range (33, 126);
		/* too many non alphanumeric characters are hard to remember for humans */
		while (!g_ascii_isalnum (c))
			c = g_random_int_range (33, 126);

		key[i] = (gchar) c;
	}
	key[WPA_PASSKEY_SIZE] = '\0';
}

static void
generate_wep_key (char *key, size_t len)
{
	int i;
	const char *hexdigits = "0123456789abcdef";

	g_return_if_fail (key);
	g_return_if_fail (len > 10);

	/* generate a 10-digit hex WEP key */
	for (i = 0; i < 10; i++) {
		int digit;
		digit = g_random_int_range (0, 16);
		key[i] = hexdigits[digit];
	}
	key[10] = '\0';
}

static gboolean
set_wireless_security_for_hotspot (NMSettingWirelessSecurity *s_wsec,
                                   const char *wifi_mode,
                                   NMDeviceWifiCapabilities caps,
                                   const char *password,
                                   gboolean show_password,
                                   GError **error)
{
        char generated_key[11];
	const char *key;
	const char *key_mgmt;

	if (g_strcmp0 (wifi_mode, NM_SETTING_WIRELESS_MODE_AP) == 0) {
		if (caps & NM_WIFI_DEVICE_CAP_RSN) {
			nm_setting_wireless_security_add_proto (s_wsec, "rsn");
			nm_setting_wireless_security_add_pairwise (s_wsec, "ccmp");
			nm_setting_wireless_security_add_group (s_wsec, "ccmp");
			key_mgmt = "wpa-psk";
		} else if (caps & NM_WIFI_DEVICE_CAP_WPA) {
			nm_setting_wireless_security_add_proto (s_wsec, "wpa");
			nm_setting_wireless_security_add_pairwise (s_wsec, "tkip");
			nm_setting_wireless_security_add_group (s_wsec, "tkip");
			key_mgmt = "wpa-psk";
		} else
			key_mgmt = "none";
	} else
		key_mgmt = "none";

	if (g_strcmp0 (key_mgmt, "wpa-psk") == 0) {
		/* use WPA */
		if (password) {
			if (!nm_utils_wpa_psk_valid (password)) {
				g_set_error (error, NMCLI_ERROR, 0, _("'%s' is not valid WPA PSK"), password);
				return FALSE;
			}
			key = password;
		} else {
			generate_wpa_key (generated_key, sizeof (generated_key));
			key = generated_key;
		}
		g_object_set (s_wsec,
		              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, key_mgmt,
		              NM_SETTING_WIRELESS_SECURITY_PSK, key,
		              NULL);
	} else {
		/* use WEP */
		if (password) {
			if (!nm_utils_wep_key_valid (password, NM_WEP_KEY_TYPE_KEY)) {
				g_set_error (error, NMCLI_ERROR, 0,
				             _("'%s' is not valid WEP key (it should be 5 or 13 ASCII chars)"),
				             password);
				return FALSE;
			}
			key = password;
		} else {
			generate_wep_key (generated_key, sizeof (generated_key));
			key = generated_key;
		}
		g_object_set (s_wsec,
		              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, key_mgmt,
		              NM_SETTING_WIRELESS_SECURITY_WEP_KEY0, key,
		              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, NM_WEP_KEY_TYPE_KEY,
		              NULL);
	}
	if (show_password)
		g_print (_("Hotspot password: %s\n"), key);

	return TRUE;
}

static NMCResultCode
do_device_wifi_hotspot (NmCli *nmc, int argc, char **argv)
{
	AddAndActivateInfo *info;
	const char *ifname = NULL;
	const char *con_name = NULL;
	char *default_name = NULL;
	const char *ssid = NULL;
	const char *wifi_mode;
	const char *band = NULL;
	const char *channel = NULL;
	unsigned long channel_int;
	const char *password = NULL;
	gboolean show_password = FALSE;
	NMDevice *device = NULL;
	gs_free NMDevice **devices = NULL;
	NMDeviceWifiCapabilities caps;
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIPConfig *s_ip4, *s_ip6;
	NMSettingProxy *s_proxy;
	GBytes *ssid_bytes;
	GError *error = NULL;

	/* Set default timeout waiting for operation completion. */
	if (nmc->timeout == -1)
		nmc->timeout = 60;

	devices = nmc_get_devices_sorted (nmc->client);

	next_arg (nmc, &argc, &argv, NULL);
	while (argc > 0) {
		if (argc == 1 && nmc->complete) {
			nmc_complete_strings (*argv, "ifname", "con-name", "ssid", "band",
			                             "channel", "password", NULL);
		}

		if (strcmp (*argv, "ifname") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				return NMC_RESULT_ERROR_USER_INPUT;
			}
			ifname = *argv;
			if (argc == 1 && nmc->complete)
				complete_device (devices, ifname, TRUE);
		} else if (strcmp (*argv, "con-name") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				return NMC_RESULT_ERROR_USER_INPUT;
			}
			con_name = *argv;
		} else if (strcmp (*argv, "ssid") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				return NMC_RESULT_ERROR_USER_INPUT;
			}
			ssid = *argv;
			if (strlen (ssid) > 32) {
				g_string_printf (nmc->return_text, _("Error: ssid is too long."));
				return NMC_RESULT_ERROR_USER_INPUT;
			}
		} else if (strcmp (*argv, "band") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				return NMC_RESULT_ERROR_USER_INPUT;
			}
			band = *argv;
			if (argc == 1 && nmc->complete)
				nmc_complete_strings (band, "a", "bg", NULL);
			if (strcmp (band, "a") && strcmp (band, "bg")) {
				g_string_printf (nmc->return_text, _("Error: band argument value '%s' is invalid; use 'a' or 'bg'."),
				                 band);
				return NMC_RESULT_ERROR_USER_INPUT;
			}
		} else if (strcmp (*argv, "channel") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				return NMC_RESULT_ERROR_USER_INPUT;
			}
			channel = *argv;
		} else if (strcmp (*argv, "password") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				return NMC_RESULT_ERROR_USER_INPUT;
			}
			password = *argv;
		/* --show-password is deprecated in favour of global --show-secrets option */
		/* Keep it here for backwards compatibility */
		} else if (nmc_arg_is_option (*argv, "show-password")) {
			show_password = TRUE;
		} else {
			g_string_printf (nmc->return_text, _("Error: Unknown parameter %s."), *argv);
			return NMC_RESULT_ERROR_USER_INPUT;
		}

		next_arg (nmc, &argc, &argv, NULL);
	}
	show_password = nmc->nmc_config.show_secrets || show_password;

	if (nmc->complete)
		return nmc->return_value;

	/* Verify band and channel parameters */
	if (!channel) {
		if (g_strcmp0 (band, "bg") == 0)
			channel = "1";
		if (g_strcmp0 (band, "a") == 0)
			channel = "7";
	}
	if (channel) {
		if (!band) {
			g_string_printf (nmc->return_text, _("Error: channel requires band too."));
			return NMC_RESULT_ERROR_USER_INPUT;
		}
		if (   !nmc_string_to_uint (channel, TRUE, 1, 5825, &channel_int)
		    || !nm_utils_wifi_is_channel_valid (channel_int, band)) {
			g_string_printf (nmc->return_text, _("Error: channel '%s' not valid for band '%s'."),
			                 channel, band);
			return NMC_RESULT_ERROR_USER_INPUT;
		}
	}

	/* Find Wi-Fi device. When no ifname is provided, the first Wi-Fi is used. */
	device = find_wifi_device_by_iface (devices, ifname, NULL);

	if (!device) {
		if (ifname)
			g_string_printf (nmc->return_text, _("Error: Device '%s' is not a Wi-Fi device."), ifname);
		else
			g_string_printf (nmc->return_text, _("Error: No Wi-Fi device found."));
		return NMC_RESULT_ERROR_UNKNOWN;
	}

	/* Check device supported mode */
	caps = nm_device_wifi_get_capabilities (NM_DEVICE_WIFI (device));
	if (caps & NM_WIFI_DEVICE_CAP_AP)
		wifi_mode = NM_SETTING_WIRELESS_MODE_AP;
	else if (caps & NM_WIFI_DEVICE_CAP_ADHOC)
		wifi_mode = NM_SETTING_WIRELESS_MODE_ADHOC;
	else {
		g_string_printf (nmc->return_text, _("Error: Device '%s' supports neither AP nor Ad-Hoc mode."),
		                 nm_device_get_iface (device));
		return NMC_RESULT_ERROR_UNKNOWN;
	}

	/* Create a connection with appropriate parameters */
	connection = nm_simple_connection_new ();
	s_con =  (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	if (!con_name)
		con_name = default_name = nmc_unique_connection_name (nm_client_get_connections (nmc->client), "Hotspot");
	g_object_set (s_con,
                      NM_SETTING_CONNECTION_ID, con_name,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NULL);
	g_free (default_name);

	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));
	ssid_bytes = generate_ssid_for_hotspot (ssid);
	g_object_set (s_wifi, NM_SETTING_WIRELESS_MODE, wifi_mode,
	                      NM_SETTING_WIRELESS_SSID, ssid_bytes,
	                      NULL);
	g_bytes_unref (ssid_bytes);
	if (channel)
		g_object_set (s_wifi,
		              NM_SETTING_WIRELESS_CHANNEL, (guint32) channel_int,
		              NM_SETTING_WIRELESS_BAND, band,
		              NULL);

	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));
	if (!set_wireless_security_for_hotspot (s_wsec, wifi_mode, caps, password, show_password, &error)) {
		g_object_unref (connection);
		g_string_printf (nmc->return_text, _("Error: Invalid 'password': %s."), error->message);
		g_clear_error (&error);
		return NMC_RESULT_ERROR_UNKNOWN;
	}

	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_SHARED, NULL);

	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	g_object_set (s_ip6, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE, NULL);

	s_proxy = (NMSettingProxy *) nm_setting_proxy_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_proxy));
	g_object_set (s_proxy, NM_SETTING_PROXY_METHOD, (int) NM_SETTING_PROXY_METHOD_NONE, NULL);

	/* Activate the connection now */
	nmc->nowait_flag = (nmc->timeout == 0);
	nmc->should_wait++;

	info = g_malloc0 (sizeof (AddAndActivateInfo));
	info->nmc = nmc;
	info->device = device;
	info->hotspot = TRUE;

	nm_client_add_and_activate_connection_async (nmc->client,
	                                             connection,
	                                             device,
	                                             NULL,
	                                             NULL,
	                                             add_and_activate_cb,
	                                             info);

	return nmc->return_value;
}

static void
request_rescan_cb (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;
	GError *error = NULL;

	nm_device_wifi_request_scan_finish (NM_DEVICE_WIFI (object), result, &error);
	if (error) {
		g_string_printf (nmc->return_text, _("Error: %s."), error->message);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		g_error_free (error);
	}
	quit ();
}

static NMCResultCode
do_device_wifi_rescan (NmCli *nmc, int argc, char **argv)
{
	NMDevice *device;
	const char *ifname = NULL;
	GPtrArray *ssids;
	gs_free NMDevice **devices = NULL;
	GVariantBuilder builder, array_builder;
	GVariant *options;
	const char *ssid;
	int i;

	ssids = g_ptr_array_new ();
	devices = nmc_get_devices_sorted (nmc->client);

	next_arg (nmc, &argc, &argv, NULL);
	/* Get the parameters */
	while (argc > 0) {
		if (argc == 1 && nmc->complete)
			nmc_complete_strings (*argv, "ifname", "ssid", NULL);

		if (strcmp (*argv, "ifname") == 0) {
			if (ifname) {
				g_string_printf (nmc->return_text, _("Error: '%s' cannot repeat."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
			ifname = *argv;
			if (argc == 1 && nmc->complete)
				complete_device (devices, ifname, TRUE);
		} else if (strcmp (*argv, "ssid") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto finish;
			}
			g_ptr_array_add (ssids, *argv);
		} else if (!nmc->complete)
			g_printerr (_("Unknown parameter: %s\n"), *argv);

		next_arg (nmc, &argc, &argv, NULL);
	}

	if (nmc->complete)
		goto finish;

	/* Find Wi-Fi device to scan on. When no ifname is provided, the first Wi-Fi is used. */
	device = find_wifi_device_by_iface (devices, ifname, NULL);

	if (!device) {
		if (ifname)
			g_string_printf (nmc->return_text, _("Error: Device '%s' is not a Wi-Fi device."), ifname);
		else
			g_string_printf (nmc->return_text, _("Error: No Wi-Fi device found."));
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto finish;
	}


	if (ssids->len) {
		g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
		g_variant_builder_init (&array_builder, G_VARIANT_TYPE ("aay"));

		for (i = 0; i < ssids->len; i++) {
			ssid = g_ptr_array_index (ssids, i);
			g_variant_builder_add (&array_builder, "@ay",
			                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, ssid, strlen (ssid), 1));
		}

		g_variant_builder_add (&builder, "{sv}", "ssids", g_variant_builder_end (&array_builder));
		options = g_variant_builder_end (&builder);

		nm_device_wifi_request_scan_options_async (NM_DEVICE_WIFI (device), options,
		                                           NULL, request_rescan_cb, nmc);
	} else
		nm_device_wifi_request_scan_async (NM_DEVICE_WIFI (device),
		                                   NULL, request_rescan_cb, nmc);

	nmc->should_wait++;
finish:
	g_ptr_array_free (ssids, FALSE);
	return nmc->return_value;
}

static NMCCommand device_wifi_cmds[] = {
	{ "list",     do_device_wifi_list,            NULL,             TRUE,   TRUE },
	{ "connect",  do_device_wifi_connect_network, NULL,             TRUE,   TRUE },
	{ "hotspot",  do_device_wifi_hotspot,         NULL,             TRUE,   TRUE },
	{ "rescan",   do_device_wifi_rescan,          NULL,             TRUE,   TRUE },
	{ NULL,       do_device_wifi_list,            NULL,             TRUE,   TRUE },
};

static NMCResultCode
do_device_wifi (NmCli *nmc, int argc, char **argv)
{
	next_arg (nmc, &argc, &argv, NULL);
	nmc_do_cmd (nmc, device_wifi_cmds, *argv, argc, argv);

	return nmc->return_value;
}

static int
show_device_lldp_list (NMDevice *device, NmCli *nmc, const char *fields_str, int *counter)
{
	const NMMetaAbstractInfo *const*tmpl;
	NmcOutputField *arr;
	GPtrArray *neighbors;
	const char *str;
	int i;
	NMC_OUTPUT_DATA_DEFINE_SCOPED (out);
	gs_free char *header_name = NULL;

	neighbors = nm_device_get_lldp_neighbors (device);

	if (!neighbors || !neighbors->len)
		return 0;

	tmpl = (const NMMetaAbstractInfo *const*) nmc_fields_dev_lldp_list;

	/* Main header name */
	header_name = construct_header_name (_("Device LLDP neighbors"),
	                                     nm_device_get_iface (device));
	out_indices = parse_output_fields (fields_str, (const NMMetaAbstractInfo *const*) nmc_fields_dev_lldp_list, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (out.output_data, arr);

	for (i = 0; i < neighbors->len; i++) {
		NMLldpNeighbor *neighbor = neighbors->pdata[i];
		guint value;

		arr = nmc_dup_fields_array (tmpl, NMC_OF_FLAG_SECTION_PREFIX);
		set_val_str (arr, 0, g_strdup_printf ("NEIGHBOR[%d]", (*counter)++));

		set_val_strc (arr, 1, nm_device_get_iface (device));

		if (nm_lldp_neighbor_get_attr_string_value (neighbor, NM_LLDP_ATTR_CHASSIS_ID, &str))
			set_val_strc (arr, 2, str);

		if (nm_lldp_neighbor_get_attr_string_value (neighbor, NM_LLDP_ATTR_PORT_ID, &str))
			set_val_strc (arr, 3, str);

		if (nm_lldp_neighbor_get_attr_string_value (neighbor, NM_LLDP_ATTR_PORT_DESCRIPTION, &str))
			set_val_strc (arr, 4, str);

		if (nm_lldp_neighbor_get_attr_string_value (neighbor, NM_LLDP_ATTR_SYSTEM_NAME, &str))
			set_val_strc (arr, 5, str);

		if (nm_lldp_neighbor_get_attr_string_value (neighbor, NM_LLDP_ATTR_SYSTEM_DESCRIPTION, &str))
			set_val_strc (arr, 6, str);

		if (nm_lldp_neighbor_get_attr_uint_value (neighbor, NM_LLDP_ATTR_SYSTEM_CAPABILITIES, &value))
			set_val_str (arr, 7, g_strdup_printf ("%u (%s)", value, nmc_parse_lldp_capabilities (value)));

		if (nm_lldp_neighbor_get_attr_uint_value (neighbor, NM_LLDP_ATTR_IEEE_802_1_PVID, &value))
			set_val_str (arr, 8, g_strdup_printf ("%u", value));

		if (nm_lldp_neighbor_get_attr_uint_value (neighbor, NM_LLDP_ATTR_IEEE_802_1_PPVID, &value))
			set_val_str (arr, 9, g_strdup_printf ("%u", value));

		if (nm_lldp_neighbor_get_attr_uint_value (neighbor, NM_LLDP_ATTR_IEEE_802_1_PPVID_FLAGS, &value))
			set_val_str (arr, 10, g_strdup_printf ("%u", value));

		if (nm_lldp_neighbor_get_attr_uint_value (neighbor, NM_LLDP_ATTR_IEEE_802_1_VID, &value))
			set_val_str (arr, 11, g_strdup_printf ("%u", value));

		if (nm_lldp_neighbor_get_attr_string_value (neighbor, NM_LLDP_ATTR_IEEE_802_1_VLAN_NAME, &str))
			set_val_strc (arr, 12, str);

		if (nm_lldp_neighbor_get_attr_string_value (neighbor, NM_LLDP_ATTR_DESTINATION, &str))
			set_val_strc (arr, 13, str);

		if (nm_lldp_neighbor_get_attr_uint_value (neighbor, NM_LLDP_ATTR_CHASSIS_ID_TYPE, &value))
			set_val_strc (arr, 14, g_strdup_printf ("%u", value));

		if (nm_lldp_neighbor_get_attr_uint_value (neighbor, NM_LLDP_ATTR_PORT_ID_TYPE, &value))
			set_val_strc (arr, 15, g_strdup_printf ("%u", value));

		g_ptr_array_add (out.output_data, arr);
	}

	print_data_prepare_width (out.output_data);
	print_data (&nmc->nmc_config, out_indices, header_name, 0, &out);

	return neighbors->len;
}

static NMCResultCode
do_device_lldp_list (NmCli *nmc, int argc, char **argv)
{
	NMDevice *device = NULL;
	gs_free_error GError *error = NULL;
	const char *fields_str = NULL;
	int counter = 0;
	gs_unref_array GArray *out_indices = NULL;

	next_arg (nmc, &argc, &argv, NULL);
	while (argc > 0) {
		if (argc == 1 && nmc->complete)
			nmc_complete_strings (*argv, "ifname", NULL);

		if (strcmp (*argv, "ifname") == 0) {
			argc--;
			argv++;
			if (!argc) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				return NMC_RESULT_ERROR_USER_INPUT;
			}

			device = get_device (nmc, &argc, &argv, &error);
			if (!device) {
				g_string_printf (nmc->return_text, _("Error: %s."), error->message);
				return error->code;
			}
		} else {
			g_string_printf (nmc->return_text, _("Error: invalid extra argument '%s'."), *argv);
			return NMC_RESULT_ERROR_USER_INPUT;
		}

		next_arg (nmc, &argc, &argv, NULL);
	}

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = NMC_FIELDS_DEV_LLDP_LIST_COMMON;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0) {
	} else
		fields_str = nmc->required_fields;

	out_indices = parse_output_fields (fields_str, (const NMMetaAbstractInfo *const*) nmc_fields_dev_lldp_list, FALSE, NULL, &error);

	if (error) {
		g_string_printf (nmc->return_text, _("Error: 'device lldp list': %s"), error->message);
		return NMC_RESULT_ERROR_USER_INPUT;
	}

	if (nmc->complete)
		return nmc->return_value;

	if (device) {
		show_device_lldp_list (device, nmc, fields_str, &counter);
	} else {
		NMDevice **devices = nmc_get_devices_sorted (nmc->client);
		int i;

		for (i = 0; devices[i]; i++)
			show_device_lldp_list (devices[i], nmc, fields_str, &counter);

		g_free (devices);
	}

	return nmc->return_value;
}

static NMCCommand device_lldp_cmds[] = {
	{ "list",  do_device_lldp_list,  NULL,             TRUE,   TRUE },
	{ NULL,    do_device_lldp_list,  NULL,             TRUE,   TRUE },
};

static NMCResultCode
do_device_lldp (NmCli *nmc, int argc, char **argv)
{
	if (!nmc->mode_specified)
		nmc->nmc_config_mutable.multiline_output = TRUE;  /* multiline mode is default for 'device lldp' */

	next_arg (nmc, &argc, &argv, NULL);
	nmc_do_cmd (nmc, device_lldp_cmds, *argv, argc, argv);

	return nmc->return_value;
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
nmcli_device_tab_completion (const char *text, int start, int end)
{
	char **match_array = NULL;
	rl_compentry_func_t *generator_func = NULL;

	/* Disable readline's default filename completion */
	rl_attempted_completion_over = 1;

	if (g_strcmp0 (rl_prompt, PROMPT_INTERFACE) == 0) {
		/* Disable appending space after completion */
		rl_completion_append_character = '\0';

		if (!is_single_word (rl_line_buffer))
			return NULL;

		generator_func = nmc_rl_gen_func_ifnames;
	} else if (g_strcmp0 (rl_prompt, PROMPT_INTERFACES) == 0) {
		generator_func = nmc_rl_gen_func_ifnames;
	}

	if (generator_func)
		match_array = rl_completion_matches (text, generator_func);

	return match_array;
}

static const NMCCommand device_cmds[] = {
	{ "status",      do_devices_status,      usage_device_status,      TRUE,   TRUE },
	{ "show",        do_device_show,         usage_device_show,        TRUE,   TRUE },
	{ "connect",     do_device_connect,      usage_device_connect,     TRUE,   TRUE },
	{ "reapply",     do_device_reapply,      usage_device_reapply,     TRUE,   TRUE },
	{ "disconnect",  do_devices_disconnect,  usage_device_disconnect,  TRUE,   TRUE },
	{ "delete",      do_devices_delete,      usage_device_delete,      TRUE,   TRUE },
	{ "set",         do_device_set,          usage_device_set,         TRUE,   TRUE },
	{ "monitor",     do_devices_monitor,     usage_device_monitor,     TRUE,   TRUE },
	{ "wifi",        do_device_wifi,         usage_device_wifi,        FALSE,  FALSE },
	{ "lldp",        do_device_lldp,         usage_device_lldp,        FALSE,  FALSE },
	{ "modify",      do_device_modify,       usage_device_modify,      TRUE,   TRUE },
	{ NULL,          do_devices_status,      usage,                    TRUE,   TRUE },
};

NMCResultCode
do_devices (NmCli *nmc, int argc, char **argv)
{
	next_arg (nmc, &argc, &argv, NULL);

	/* Register polkit agent */
	nmc_start_polkit_agent_start_try (nmc);

	rl_attempted_completion_function = (rl_completion_func_t *) nmcli_device_tab_completion;

	nmc_do_cmd (nmc, device_cmds, *argv, argc, argv);

	return nmc->return_value;
}

void
monitor_devices (NmCli *nmc)
{
	do_devices_monitor (nmc, 0, NULL);
}
