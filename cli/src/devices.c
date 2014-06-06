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
 * (C) Copyright 2010 - 2014 Red Hat, Inc.
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/ether.h>
#include <readline/readline.h>

#include <glib.h>
#include <glib/gi18n.h>

#include <nm-client.h>
#include <nm-device.h>
#include <nm-device-ethernet.h>
#include <nm-device-adsl.h>
#include <nm-device-wifi.h>
#include <nm-device-modem.h>
#include <nm-device-bt.h>
#include <nm-device-olpc-mesh.h>
#if WITH_WIMAX
#include <nm-device-wimax.h>
#endif
#include <nm-device-infiniband.h>
#include <nm-device-bond.h>
#include <nm-device-bridge.h>
#include <nm-device-vlan.h>
#include <nm-utils.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-vpn-connection.h>
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-adsl.h>
#include <nm-setting-pppoe.h>
#include <nm-setting-wireless.h>
#include <nm-setting-gsm.h>
#include <nm-setting-cdma.h>
#include <nm-setting-bluetooth.h>
#include <nm-setting-olpc-mesh.h>
#if WITH_WIMAX
#include <nm-setting-wimax.h>
#endif
#include <nm-setting-infiniband.h>

#include "utils.h"
#include "common.h"
#include "devices.h"

/* define some prompts */
#define PROMPT_INTERFACE _("Interface: ")

/* Available fields for 'device status' */
static NmcOutputField nmc_fields_dev_status[] = {
	{"DEVICE",     N_("DEVICE"),     10},  /* 0 */
	{"TYPE",       N_("TYPE"),       17},  /* 1 */
	{"STATE",      N_("STATE"),      13},  /* 2 */
	{"DBUS-PATH",  N_("DBUS-PATH"),  43},  /* 3 */
	{"CONNECTION", N_("CONNECTION"), 20},  /* 4 */
	{"CON-UUID",   N_("CON-UUID"),   38},  /* 5 */
	{"CON-PATH",   N_("CON-PATH"),   51},  /* 6 */
	{NULL,         NULL,              0}
};
#define NMC_FIELDS_DEV_STATUS_ALL     "DEVICE,TYPE,STATE,DBUS-PATH,CONNECTION,CON-UUID,CON-PATH"
#define NMC_FIELDS_DEV_STATUS_COMMON  "DEVICE,TYPE,STATE,CONNECTION"


/* Available fields for 'device show' - GENERAL part */
static NmcOutputField nmc_fields_dev_show_general[] = {
	{"NAME",              N_("NAME"),              10},  /* 0 */
	{"DEVICE",            N_("DEVICE"),            10},  /* 1 */
	{"TYPE",              N_("TYPE"),              17},  /* 2 */
	{"VENDOR",            N_("VENDOR"),            20},  /* 3 */
	{"PRODUCT",           N_("PRODUCT"),           50},  /* 4 */
	{"DRIVER",            N_("DRIVER"),             9},  /* 5 */
	{"DRIVER-VERSION",    N_("DRIVER-VERSION"),    18},  /* 6 */
	{"FIRMWARE-VERSION",  N_("FIRMWARE-VERSION"),  18},  /* 7 */
	{"HWADDR",            N_("HWADDR"),            19},  /* 8 */
	{"MTU",               N_("MTU"),               10},  /* 9 */
	{"STATE",             N_("STATE"),             14},  /* 10 */
	{"REASON",            N_("REASON"),            25},  /* 11 */
	{"UDI",               N_("UDI"),               64},  /* 12 */
	{"IP-IFACE",          N_("IP-IFACE"),          10},  /* 13 */
	{"NM-MANAGED",        N_("NM-MANAGED"),        15},  /* 14 */
	{"AUTOCONNECT",       N_("AUTOCONNECT"),       15},  /* 15 */
	{"FIRMWARE-MISSING",  N_("FIRMWARE-MISSING"),  18},  /* 16 */
	{"CONNECTION",        N_("CONNECTION"),        20},  /* 17 */
	{"CON-UUID",          N_("CON-UUID"),          38},  /* 18 */
	{"CON-PATH",          N_("CON-PATH"),          51},  /* 19 */
	{NULL, NULL, 0}
};
#define NMC_FIELDS_DEV_SHOW_GENERAL_ALL     "NAME,DEVICE,TYPE,VENDOR,PRODUCT,DRIVER,DRIVER-VERSION,FIRMWARE-VERSION,HWADDR,MTU,STATE,REASON,"\
                                            "UDI,IP-IFACE,NM-MANAGED,AUTOCONNECT,FIRMWARE-MISSING,CONNECTION,CON-UUID,CON-PATH"
#define NMC_FIELDS_DEV_SHOW_GENERAL_COMMON  "NAME,DEVICE,TYPE,VENDOR,PRODUCT,DRIVER,HWADDR,STATE"

/* Available fields for 'device show' - CONNECTIONS part */
static NmcOutputField nmc_fields_dev_show_connections[] = {
	{"NAME",                       N_("NAME"),                       10},  /* 0 */
	{"AVAILABLE-CONNECTION-PATHS", N_("AVAILABLE-CONNECTION-PATHS"), 80},  /* 1 */
	{"AVAILABLE-CONNECTIONS",      N_("AVAILABLE-CONNECTIONS"),      80},  /* 2 */
	{NULL, NULL, 0}
};
#define NMC_FIELDS_DEV_SHOW_CONNECTIONS_ALL     "AVAILABLE-CONNECTION-PATHS,AVAILABLE-CONNECTIONS"
#define NMC_FIELDS_DEV_SHOW_CONNECTIONS_COMMON  "AVAILABLE-CONNECTION-PATHS,AVAILABLE-CONNECTIONS"

/* Available fields for 'device show' - CAPABILITIES part */
static NmcOutputField nmc_fields_dev_show_cap[] = {
	{"NAME",            N_("NAME"),            13},  /* 0 */
	{"CARRIER-DETECT",  N_("CARRIER-DETECT"),  16},  /* 1 */
	{"SPEED",           N_("SPEED"),           10},  /* 2 */
	{NULL,              NULL,                   0}
};
#define NMC_FIELDS_DEV_SHOW_CAP_ALL     "NAME,CARRIER-DETECT,SPEED"
#define NMC_FIELDS_DEV_SHOW_CAP_COMMON  "NAME,CARRIER-DETECT,SPEED"

/* Available fields for 'device show' - wired properties part */
static NmcOutputField nmc_fields_dev_show_wired_prop[] = {
	{"NAME",            N_("NAME"),     18},  /* 0 */
	{"CARRIER",         N_("CARRIER"),  10},  /* 1 */
	{NULL,              NULL,            0}
};
#define NMC_FIELDS_DEV_SHOW_WIRED_PROP_ALL     "NAME,CARRIER"
#define NMC_FIELDS_DEV_SHOW_WIRED_PROP_COMMON  "NAME,CARRIER"

/* Available fields for 'device show' - wireless properties part */
static NmcOutputField nmc_fields_dev_show_wifi_prop[] = {
	{"NAME",       N_("NAME"),   18},  /* 0 */
	{"WEP",        N_("WEP"),     5},  /* 1 */
	{"WPA",        N_("WPA"),     5},  /* 2 */
	{"WPA2",       N_("WPA2"),    6},  /* 3 */
	{"TKIP",       N_("TKIP"),    6},  /* 4 */
	{"CCMP",       N_("CCMP"),    6},  /* 5 */
	{"AP",         N_("AP"),      6},  /* 6 */
	{"ADHOC",      N_("ADHOC"),   6},  /* 7 */
	{NULL,         NULL,          0}
};
#define NMC_FIELDS_DEV_SHOW_WIFI_PROP_ALL     "NAME,WEP,WPA,WPA2,TKIP,CCMP,AP,ADHOC"
#define NMC_FIELDS_DEV_SHOW_WIFI_PROP_COMMON  "NAME,WEP,WPA,WPA2,TKIP,CCMP,AP,ADHOC"

/* Available fields for 'device show' - wimax properties part */
static NmcOutputField nmc_fields_dev_show_wimax_prop[] = {
	{"NAME",       N_("NAME"),     18},  /* 0 */
	{"CTR-FREQ",   N_("CTR-FREQ"),  7},  /* 1 */
	{"RSSI",       N_("RSSI"),      5},  /* 2 */
	{"CINR",       N_("CINR"),      5},  /* 3 */
	{"TX-POW",     N_("TX-POW"),    5},  /* 4 */
	{"BSID",       N_("BSID"),     18},  /* 5 */
	{NULL,         NULL,            0}
};
#define NMC_FIELDS_DEV_SHOW_WIMAX_PROP_ALL     "NAME,CTR-FREQ,RSSI,CINR,TX-POW,BSID"
#define NMC_FIELDS_DEV_SHOW_WIMAX_PROP_COMMON  "NAME,CTR-FREQ,RSSI,CINR,TX-POW,BSID"

/* Available fields for 'device wifi list' */
static NmcOutputField nmc_fields_dev_wifi_list[] = {
	{"NAME",       N_("NAME"),       15},  /* 0 */
	{"SSID",       N_("SSID"),       33},  /* 1 */
	{"SSID-HEX",   N_("SSID-HEX"),   66},  /* 2 */
	{"BSSID",      N_("BSSID"),      19},  /* 3 */
	{"MODE",       N_("MODE"),       16},  /* 4 */
	{"CHAN",       N_("CHAN"),        6},  /* 5 */
	{"FREQ",       N_("FREQ"),       10},  /* 6 */
	{"RATE",       N_("RATE"),       10},  /* 7 */
	{"SIGNAL",     N_("SIGNAL"),      8},  /* 8 */
	{"BARS",       N_("BARS"),        6},  /* 9 */
	{"SECURITY",   N_("SECURITY"),   10},  /* 10 */
	{"WPA-FLAGS",  N_("WPA-FLAGS"),  25},  /* 11 */
	{"RSN-FLAGS",  N_("RSN-FLAGS"),  25},  /* 12 */
	{"DEVICE",     N_("DEVICE"),     10},  /* 13 */
	{"ACTIVE",     N_("ACTIVE"),      8},  /* 14 */
	{"IN-USE",     N_("*"),           1},  /* 15 */
	{"DBUS-PATH",  N_("DBUS-PATH"),  46},  /* 16 */
	{NULL,         NULL,              0}
};
#define NMC_FIELDS_DEV_WIFI_LIST_ALL           "SSID,SSID-HEX,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY,"\
                                               "WPA-FLAGS,RSN-FLAGS,DEVICE,ACTIVE,IN-USE,DBUS-PATH"
#define NMC_FIELDS_DEV_WIFI_LIST_COMMON        "IN-USE,SSID,MODE,CHAN,RATE,SIGNAL,BARS,SECURITY"
#define NMC_FIELDS_DEV_WIFI_LIST_FOR_DEV_LIST  "NAME,"NMC_FIELDS_DEV_WIFI_LIST_COMMON

/* Available fields for 'device wimax list' */
static NmcOutputField nmc_fields_dev_wimax_list[] = {
	{"NAME",       N_("NAME"),        15},  /* 0 */
	{"NSP",        N_("NSP"),         33},  /* 1 */
	{"SIGNAL",     N_("SIGNAL"),       8},  /* 2 */
	{"TYPE",       N_("TYPE"),        16},  /* 3 */
	{"DEVICE",     N_("DEVICE"),      10},  /* 4 */
	{"ACTIVE",     N_("ACTIVE"),       8},  /* 5 */
	{"DBUS-PATH",  N_("DBUS-PATH"),   46},  /* 6 */
	{NULL,         NULL,               0}
};
#define NMC_FIELDS_DEV_WIMAX_LIST_ALL           "NSP,SIGNAL,TYPE,DEVICE,ACTIVE,DBUS-PATH"
#define NMC_FIELDS_DEV_WIMAX_LIST_COMMON        "NSP,SIGNAL,TYPE,DEVICE,ACTIVE"
#define NMC_FIELDS_DEV_WIMAX_LIST_FOR_DEV_LIST  "NAME,"NMC_FIELDS_DEV_WIMAX_LIST_COMMON

/* Available fields for 'device show' - BOND part */
static NmcOutputField nmc_fields_dev_show_bond_prop[] = {
	{"NAME",           N_("NAME"),     18},  /* 0 */
	{"SLAVES",         N_("SLAVES"),   20},  /* 1 */
	{NULL,             NULL,            0}
};
#define NMC_FIELDS_DEV_SHOW_BOND_PROP_ALL     "NAME,SLAVES"
#define NMC_FIELDS_DEV_SHOW_BOND_PROP_COMMON  "NAME,SLAVES"

/* Available fields for 'device show' - VLAN part */
static NmcOutputField nmc_fields_dev_show_vlan_prop[] = {
	{"NAME",           N_("NAME"),     18},  /* 0 */
	{"ID",             N_("ID"),        5},  /* 1 */
	{NULL,             NULL,            0}
};
#define NMC_FIELDS_DEV_SHOW_VLAN_PROP_ALL     "NAME,ID"
#define NMC_FIELDS_DEV_SHOW_VLAN_PROP_COMMON  "NAME,ID"

/* defined in common.c */
extern NmcOutputField nmc_fields_ip4_config[];
extern NmcOutputField nmc_fields_ip6_config[];
extern NmcOutputField nmc_fields_dhcp4_config[];
extern NmcOutputField nmc_fields_dhcp6_config[];

/* Available sections for 'device show' */
static NmcOutputField nmc_fields_dev_show_sections[] = {
	{"GENERAL",           N_("GENERAL"),           0, nmc_fields_dev_show_general + 1     },  /* 0 */
	{"CAPABILITIES",      N_("CAPABILITIES"),      0, nmc_fields_dev_show_cap + 1         },  /* 1 */
	{"WIFI-PROPERTIES",   N_("WIFI-PROPERTIES"),   0, nmc_fields_dev_show_wifi_prop + 1   },  /* 2 */
	{"AP",                N_("AP"),                0, nmc_fields_dev_wifi_list + 1        },  /* 3 */
	{"WIRED-PROPERTIES",  N_("WIRED-PROPERTIES"),  0, nmc_fields_dev_show_wired_prop + 1  },  /* 4 */
	{"WIMAX-PROPERTIES",  N_("WIMAX-PROPERTIES"),  0, nmc_fields_dev_show_wimax_prop + 1  },  /* 5 */
	{"NSP",               N_("NSP"),               0, nmc_fields_dev_wimax_list + 1       },  /* 6 */
	{"IP4",               N_("IP4"),               0, nmc_fields_ip4_config + 1           },  /* 7 */
	{"DHCP4",             N_("DHCP4"),             0, nmc_fields_dhcp4_config + 1         },  /* 8 */
	{"IP6",               N_("IP6"),               0, nmc_fields_ip6_config + 1           },  /* 9 */
	{"DHCP6",             N_("DHCP6"),             0, nmc_fields_dhcp6_config + 1         },  /* 10 */
	{"BOND",              N_("BOND"),              0, nmc_fields_dev_show_bond_prop + 1   },  /* 11 */
	{"VLAN",              N_("VLAN"),              0, nmc_fields_dev_show_vlan_prop  + 1  },  /* 12 */
	{"CONNECTIONS",       N_("CONNECTIONS"),       0, nmc_fields_dev_show_connections + 1 },  /* 13 */
	{NULL,                NULL,                    0, NULL                                }
};
#if WITH_WIMAX
#define NMC_FIELDS_DEV_SHOW_SECTIONS_ALL     "GENERAL,CAPABILITIES,BOND,VLAN,CONNECTIONS,WIFI-PROPERTIES,AP,WIRED-PROPERTIES,"\
                                             "WIMAX-PROPERTIES,NSP,IP4,DHCP4,IP6,DHCP6"
#define NMC_FIELDS_DEV_SHOW_SECTIONS_COMMON  "GENERAL.DEVICE,GENERAL.TYPE,GENERAL.HWADDR,GENERAL.MTU,GENERAL.STATE,"\
                                             "GENERAL.CONNECTION,GENERAL.CON-PATH,WIRED-PROPERTIES,IP4,IP6"
#else
#define NMC_FIELDS_DEV_SHOW_SECTIONS_ALL     "GENERAL,CAPABILITIES,BOND,VLAN,CONNECTIONS,WIFI-PROPERTIES,AP,WIRED-PROPERTIES,"\
                                             "IP4,DHCP4,IP6,DHCP6"
#define NMC_FIELDS_DEV_SHOW_SECTIONS_COMMON  "GENERAL.DEVICE,GENERAL.TYPE,GENERAL.HWADDR,GENERAL.MTU,GENERAL.STATE,"\
                                             "GENERAL.CONNECTION,GENERAL.CON-PATH,WIRED-PROPERTIES,IP4,IP6"
#endif


/* glib main loop variable - defined in nmcli.c */
extern GMainLoop *loop;

static guint progress_id = 0;  /* ID of event source for displaying progress */

static void
usage (void)
{
	fprintf (stderr,
	         _("Usage: nmcli device { COMMAND | help }\n\n"
#if WITH_WIMAX
	           "COMMAND := { status | show | connect | disconnect | wifi | wimax }\n\n"
#else
	           "COMMAND := { status | show | connect | disconnect | wifi }\n\n"
#endif
	           "  status\n\n"
	           "  show [<ifname>]\n\n"
	           "  connect <ifname>\n\n"
	           "  disconnect <ifname>\n\n"
	           "  wifi [list [ifname <ifname>] [bssid <BSSID>]]\n\n"
	           "  wifi connect <(B)SSID> [password <password>] [wep-key-type key|phrase] [ifname <ifname>]\n"
	           "                         [bssid <BSSID>] [name <name>] [private yes|no]\n\n"
	           "  wifi rescan [[ifname] <ifname>]\n\n"
#if WITH_WIMAX
	           "  wimax [list [ifname <ifname>] [nsp <name>]]\n\n"
#endif
	         ));
}

static void
usage_device_status (void)
{
	fprintf (stderr,
	         _("Usage: nmcli device status { help }\n"
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
	fprintf (stderr,
	         _("Usage: nmcli device show { ARGUMENTS | help }\n"
	           "\n"
	           "ARGUMENTS := [<ifname>]\n"
	           "\n"
	           "Show details of device(s).\n"
	           "The command lists details for all devices, or for a given device.\n\n"));
}

static void
usage_device_connect (void)
{
	fprintf (stderr,
	         _("Usage: nmcli device connect { ARGUMENTS | help }\n"
	           "\n"
	           "ARGUMENTS := <ifname>\n"
	           "\n"
	           "Connect the device.\n"
	           "NetworkManager will try to find a suitable connection that will be activated.\n"
	           "It will also consider connections that are not set to auto-connect.\n\n"));
}

static void
usage_device_disconnect (void)
{
	fprintf (stderr,
	         _("Usage: nmcli device disconnect { ARGUMENTS | help }\n"
	           "\n"
	           "ARGUMENTS := <ifname>\n"
	           "\n"
	           "Disconnect the device.\n"
	           "The command disconnects the device and prevents it from auto-activating\n"
	           "further connections without user/manual intervention.\n\n"));
}

static void
usage_device_wifi (void)
{
	fprintf (stderr,
	         _("Usage: nmcli device wifi { ARGUMENTS | help }\n"
	           "\n"
	           "Perform operation on Wi-Fi devices.\n"
	           "\n"
	           "ARGUMENTS := [list [ifname <ifname>] [bssid <BSSID>]]\n"
	           "\n"
	           "List available Wi-Fi access points. The 'ifname' and 'bssid' options can be\n"
	           "used to list APs for a particular interface, or with a specific BSSID.\n"
	           "\n"
	           "ARGUMENTS := connect <(B)SSID> [password <password>] [wep-key-type key|phrase] [ifname <ifname>]\n"
	           "                    [bssid <BSSID>] [name <name>] [private yes|no]\n"
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
	           "ARGUMENTS := rescan [[ifname] <ifname>]\n"
	           "\n"
	           "Request that NetworkManager immediately re-scan for available access points.\n"
	           "NetworkManager scans Wi-Fi networks periodically, but in some cases it might\n"
	           "be useful to start scanning manually. Note that this command does not show\n"
	           "the APs, use 'nmcli device wifi list' for that.\n\n"));
}

#if WITH_WIMAX
static void
usage_device_wimax (void)
{
	fprintf (stderr,
	         _("Usage: nmcli device wimax { ARGUMENTS | help }\n"
	           "\n"
	           "Perform operation on WiMAX devices.\n"
	           "\n"
	           "ARGUMENTS := [list [ifname <ifname>] [nsp <name>]]\n"
	           "\n"
	           "List available WiMAX NSPs. The 'ifname' and 'nsp' options can be used to\n"
	           "list networks for a particular interface, or with a specific NSP.\n\n"));
}
#endif

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

static int
compare_devices (const void *a, const void *b)
{
	NMDevice *da = *(NMDevice **)a;
	NMDevice *db = *(NMDevice **)b;
	int cmp;

	/* Sort by later device states first */
	cmp = nm_device_get_state (db) - nm_device_get_state (da);
	if (cmp != 0)
		return cmp;

	cmp = g_strcmp0 (nm_device_get_type_description (da),
	                 nm_device_get_type_description (db));
	if (cmp != 0)
		return cmp;

	return g_strcmp0 (nm_device_get_iface (da),
	                  nm_device_get_iface (db));
}

static NMDevice **
get_devices_sorted (NMClient *client)
{
	const GPtrArray *devs;
	NMDevice **sorted;

	devs = nm_client_get_devices (client);
	if (!devs) {
		sorted = g_new (NMDevice *, 1);
		sorted[0] = NULL;
		return sorted;
	}

	sorted = g_new (NMDevice *, devs->len + 1);
	memcpy (sorted, devs->pdata, devs->len * sizeof (NMDevice *));
	sorted[devs->len] = NULL;

	qsort (sorted, devs->len, sizeof (NMDevice *), compare_devices);
	return sorted;
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
	const GByteArray *ssid;
	const char *bssid;
	NM80211Mode mode;
	char *channel_str, *freq_str, *ssid_str = NULL, *ssid_hex_str = NULL,
	     *bitrate_str, *strength_str, *wpa_flags_str, *rsn_flags_str;
	GString *security_str;
	char *ap_name;
	const char *sig_level_0 = "____";
	const char *sig_level_1 = "▂___";
	const char *sig_level_2 = "▂▄__";
	const char *sig_level_3 = "▂▄▆_";
	const char *sig_level_4 = "▂▄▆█";
	const char *sig_bars;

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
		ssid_str = nm_utils_ssid_to_utf8 (ssid);
		ssid_hex_str = ssid_to_hex ((const char *) ssid->data, ssid->len);
	}
	channel_str = g_strdup_printf ("%u", nm_utils_wifi_freq_to_channel (freq));
	freq_str = g_strdup_printf (_("%u MHz"), freq);
	bitrate_str = g_strdup_printf (_("%u Mbit/s"), bitrate/1000);
	strength_str = g_strdup_printf ("%u", strength);
	wpa_flags_str = ap_wpa_rsn_flags_to_string (wpa_flags);
	rsn_flags_str = ap_wpa_rsn_flags_to_string (rsn_flags);
	sig_bars = strength > 80 ? sig_level_4 :
	           strength > 55 ? sig_level_3 :
	           strength > 30 ? sig_level_2 :
	           strength > 5  ? sig_level_1 :
	                           sig_level_0;

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

	arr = nmc_dup_fields_array (nmc_fields_dev_wifi_list,
	                            sizeof (nmc_fields_dev_wifi_list),
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

	g_ptr_array_add (info->nmc->output_data, arr);

	g_string_free (security_str, FALSE);
}

#if WITH_WIMAX
static void
fill_output_wimax_nsp (NMWimaxNsp *nsp, NmCli *nmc, NMDevice *dev, int idx, guint32 o_flags)
{
	NMDeviceWimax *wimax = NM_DEVICE_WIMAX (dev);
	char *nsp_name, *quality_str;
	const char *ntype;
	gboolean active = FALSE;
	NmcOutputField *arr;

	switch (nm_wimax_nsp_get_network_type (nsp)) {
	case NM_WIMAX_NSP_NETWORK_TYPE_HOME:
		ntype = _("Home");
		break;
	case NM_WIMAX_NSP_NETWORK_TYPE_PARTNER:
		ntype = _("Partner");
		break;
	case NM_WIMAX_NSP_NETWORK_TYPE_ROAMING_PARTNER:
		ntype = _("Roaming");
		break;
	default:
		ntype = _("Unknown");
		break;
	}

	if (nm_device_get_state (dev) == NM_DEVICE_STATE_ACTIVATED) {
		if (nsp == nm_device_wimax_get_active_nsp (wimax))
			active = TRUE;
	}

	quality_str = g_strdup_printf ("%u", nm_wimax_nsp_get_signal_quality (nsp));
	nsp_name = g_strdup_printf ("NSP[%d]", idx); /* NSP */

	arr = nmc_dup_fields_array (nmc_fields_dev_wimax_list,
	                            sizeof (nmc_fields_dev_wimax_list),
	                            o_flags);
	set_val_str  (arr, 0, nsp_name);
	set_val_strc (arr, 1, nm_wimax_nsp_get_name (nsp));
	set_val_str  (arr, 2, quality_str);
	set_val_strc (arr, 3, ntype);
	set_val_strc (arr, 4, nm_device_get_iface (dev));
	set_val_strc (arr, 5, active ? _("yes") : _("no"));
	set_val_strc (arr, 6, nm_object_get_path (NM_OBJECT (nsp)));

	g_ptr_array_add (nmc->output_data, arr);
}
#endif

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
get_active_connection_id (NMDevice *device)
{
	const GPtrArray *avail_cons;
	NMActiveConnection *ac;
	const char *ac_uuid;
	int i;

	ac = nm_device_get_active_connection (device);
	if (!ac)
		return NULL;
	ac_uuid = nm_active_connection_get_uuid (ac);

	avail_cons = nm_device_get_available_connections (device);
	for (i = 0; avail_cons && (i < avail_cons->len); i++) {
		NMRemoteConnection *candidate = g_ptr_array_index (avail_cons, i);
		const char *test_uuid = nm_connection_get_uuid (NM_CONNECTION (candidate));

		if (g_strcmp0 (ac_uuid, test_uuid) == 0)
			return nm_connection_get_id (NM_CONNECTION (candidate));
	}
	return NULL;
}

static gboolean
show_device_info (NMDevice *device, NmCli *nmc)
{
	GError *error = NULL;
	APInfo *info;
	const char *hwaddr = NULL;
	NMDeviceState state = NM_DEVICE_STATE_UNKNOWN;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	NMDeviceCapabilities caps;
	NMActiveConnection *acon;
	guint32 speed;
	char *speed_str, *state_str, *reason_str, *mtu_str;
	GArray *sections_array;
	int k;
	char *fields_str;
	char *fields_all =    NMC_FIELDS_DEV_SHOW_SECTIONS_ALL;
	char *fields_common = NMC_FIELDS_DEV_SHOW_SECTIONS_COMMON;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;
	gboolean was_output = FALSE;
	NMIP4Config *cfg4;
	NMIP6Config *cfg6;
	NMDHCP4Config *dhcp4;
	NMDHCP6Config *dhcp6;
	const char *base_hdr = _("Device details");
	GPtrArray *fields_in_section = NULL;

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else
		fields_str = nmc->required_fields;

	sections_array = parse_output_fields (fields_str, nmc_fields_dev_show_sections, TRUE, &fields_in_section, &error);
	if (error) {
		g_string_printf (nmc->return_text, _("Error: 'device show': %s"), error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return FALSE;
	}

	/* Main header */
	nmc->print_fields.header_name = (char *) construct_header_name (base_hdr, nm_device_get_iface (device));
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_DEV_SHOW_GENERAL_ALL,
	                                                 nmc_fields_dev_show_general, FALSE, NULL, NULL);

	nmc_fields_dev_show_general[0].flags = NMC_OF_FLAG_MAIN_HEADER_ONLY;
	print_required_fields (nmc, nmc_fields_dev_show_general);

	/* Loop through the required sections and print them. */
	for (k = 0; k < sections_array->len; k++) {
		int section_idx = g_array_index (sections_array, int, k);
		char *section_fld = (char *) g_ptr_array_index (fields_in_section, k);

		if (nmc->print_output != NMC_PRINT_TERSE && !nmc->multiline_output && was_output)
			printf ("\n"); /* Print empty line between groups in tabular mode */

		was_output = FALSE;

		/* Remove any previous data */
		nmc_empty_output_fields (nmc);

		state = nm_device_get_state_reason (device, &reason);

		/* section GENERAL */
		if (!strcasecmp (nmc_fields_dev_show_sections[section_idx].name, nmc_fields_dev_show_sections[0].name)) {
			tmpl = nmc_fields_dev_show_general;
			tmpl_len = sizeof (nmc_fields_dev_show_general);
			nmc->print_fields.indices = parse_output_fields (section_fld ? section_fld : NMC_FIELDS_DEV_SHOW_GENERAL_ALL,
			                                                 tmpl, FALSE, NULL, NULL);
			arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
			g_ptr_array_add (nmc->output_data, arr);

			state_str = g_strdup_printf ("%d (%s)", state, nmc_device_state_to_string (state));
			reason_str = g_strdup_printf ("%d (%s)", reason, nmc_device_reason_to_string (reason));
			hwaddr = nm_device_get_hw_address (device);
			mtu_str = g_strdup_printf ("%u", nm_device_get_mtu (device));
			acon = nm_device_get_active_connection (device);

			arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
			set_val_strc (arr, 0, nmc_fields_dev_show_sections[0].name);  /* "GENERAL"*/
			set_val_strc (arr, 1, nm_device_get_iface (device));
			set_val_strc (arr, 2, nm_device_get_type_description (device));
			set_val_strc (arr, 3, nm_device_get_vendor (device));
			set_val_strc (arr, 4, nm_device_get_product (device));
			set_val_strc (arr, 5, nm_device_get_driver (device) ? nm_device_get_driver (device) : _("(unknown)"));
			set_val_strc (arr, 6, nm_device_get_driver_version (device));
			set_val_strc (arr, 7, nm_device_get_firmware_version (device));
			set_val_strc (arr, 8, hwaddr ? hwaddr : _("(unknown)"));
			set_val_str  (arr, 9, mtu_str);
			set_val_str  (arr, 10, state_str);
			set_val_str  (arr, 11, reason_str);
			set_val_strc (arr, 12, nm_device_get_udi (device));
			set_val_strc (arr, 13, nm_device_get_ip_iface (device));
			set_val_strc (arr, 14, nm_device_get_managed (device) ? _("yes") : _("no"));
			set_val_strc (arr, 15, nm_device_get_autoconnect (device) ? _("yes") : _("no"));
			set_val_strc (arr, 16, nm_device_get_firmware_missing (device) ? _("yes") : _("no"));
			set_val_strc (arr, 17, get_active_connection_id (device));
			set_val_strc (arr, 18, acon ? nm_active_connection_get_uuid (acon) : NULL);
			set_val_strc (arr, 19, acon ? nm_object_get_path (NM_OBJECT (acon)) : NULL);
			g_ptr_array_add (nmc->output_data, arr);

			print_data (nmc);  /* Print all data */
			was_output = TRUE;
		}

		/* section CAPABILITIES */
		if (!strcasecmp (nmc_fields_dev_show_sections[section_idx].name, nmc_fields_dev_show_sections[1].name)) {
			tmpl = nmc_fields_dev_show_cap;
			tmpl_len = sizeof (nmc_fields_dev_show_cap);
			nmc->print_fields.indices = parse_output_fields (section_fld ? section_fld : NMC_FIELDS_DEV_SHOW_CAP_ALL,
			                                                 tmpl, FALSE, NULL, NULL);
			arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
			g_ptr_array_add (nmc->output_data, arr);

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

			arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
			set_val_strc (arr, 0, nmc_fields_dev_show_sections[1].name);  /* "CAPABILITIES" */
			set_val_strc (arr, 1, (caps & NM_DEVICE_CAP_CARRIER_DETECT) ? _("yes") : _("no"));
			set_val_str  (arr, 2, speed_str);
			g_ptr_array_add (nmc->output_data, arr);

			print_data (nmc);  /* Print all data */
			was_output = TRUE;
		}

		/* Wireless specific information */
		if ((NM_IS_DEVICE_WIFI (device))) {
			NMDeviceWifiCapabilities wcaps;
			NMAccessPoint *active_ap = NULL;
			const char *active_bssid = NULL;
			const GPtrArray *aps;

			/* section WIFI-PROPERTIES */
			if (!strcasecmp (nmc_fields_dev_show_sections[section_idx].name, nmc_fields_dev_show_sections[2].name)) {
				wcaps = nm_device_wifi_get_capabilities (NM_DEVICE_WIFI (device));

				tmpl = nmc_fields_dev_show_wifi_prop;
				tmpl_len = sizeof (nmc_fields_dev_show_wifi_prop);
				nmc->print_fields.indices = parse_output_fields (section_fld ? section_fld : NMC_FIELDS_DEV_SHOW_WIFI_PROP_ALL,
				                                                 tmpl, FALSE, NULL, NULL);
				arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (nmc->output_data, arr);

				arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
				set_val_strc (arr, 0, nmc_fields_dev_show_sections[2].name);  /* "WIFI-PROPERTIES" */
				set_val_strc (arr, 1, (wcaps & (NM_WIFI_DEVICE_CAP_CIPHER_WEP40 | NM_WIFI_DEVICE_CAP_CIPHER_WEP104)) ?
				                        _("yes") : _("no"));
				set_val_strc (arr, 2, (wcaps & NM_WIFI_DEVICE_CAP_WPA) ? _("yes") : _("no"));
				set_val_strc (arr, 3, (wcaps & NM_WIFI_DEVICE_CAP_RSN) ? _("yes") : _("no"));
				set_val_strc (arr, 4, (wcaps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP) ? _("yes") : _("no"));
				set_val_strc (arr, 5, (wcaps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP) ? _("yes") : _("no"));
				set_val_strc (arr, 6, (wcaps & NM_WIFI_DEVICE_CAP_AP) ? _("yes") : _("no"));
				set_val_strc (arr, 7, (wcaps & NM_WIFI_DEVICE_CAP_ADHOC) ? _("yes") : _("no"));
				g_ptr_array_add (nmc->output_data, arr);

				print_data (nmc);  /* Print all data */
				was_output = TRUE;
			}

			/* section AP */
			if (!strcasecmp (nmc_fields_dev_show_sections[section_idx].name, nmc_fields_dev_show_sections[3].name)) {
				if (state == NM_DEVICE_STATE_ACTIVATED) {
					active_ap = nm_device_wifi_get_active_access_point (NM_DEVICE_WIFI (device));
					active_bssid = active_ap ? nm_access_point_get_bssid (active_ap) : NULL;
				}

				tmpl = nmc_fields_dev_wifi_list;
				tmpl_len = sizeof (nmc_fields_dev_wifi_list);
				nmc->print_fields.indices = parse_output_fields (section_fld ? section_fld : NMC_FIELDS_DEV_WIFI_LIST_FOR_DEV_LIST,
				                                                 tmpl, FALSE, NULL, NULL);
				arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (nmc->output_data, arr);

				info = g_malloc0 (sizeof (APInfo));
				info->nmc = nmc;
				info->index = 1;
				info->output_flags = NMC_OF_FLAG_SECTION_PREFIX;
				info->active_bssid = active_bssid;
				info->device = nm_device_get_iface (device);
				aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (device));
				if (aps && aps->len)
					g_ptr_array_foreach ((GPtrArray *) aps, fill_output_access_point, (gpointer) info);
				g_free (info);
				print_data (nmc);  /* Print all data */
				was_output = TRUE;
			}
		} else if (NM_IS_DEVICE_ETHERNET (device)) {
			/* WIRED-PROPERTIES */
			if (!strcasecmp (nmc_fields_dev_show_sections[section_idx].name, nmc_fields_dev_show_sections[4].name)) {
				tmpl = nmc_fields_dev_show_wired_prop;
				tmpl_len = sizeof (nmc_fields_dev_show_wired_prop);
				nmc->print_fields.indices = parse_output_fields (section_fld ? section_fld : NMC_FIELDS_DEV_SHOW_WIRED_PROP_ALL,
				                                                 tmpl, FALSE, NULL, NULL);
				arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (nmc->output_data, arr);

				arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
				set_val_strc (arr, 0, nmc_fields_dev_show_sections[4].name);  /* "WIRED-PROPERTIES" */
				set_val_strc (arr, 1, (nm_device_ethernet_get_carrier (NM_DEVICE_ETHERNET (device))) ?
				                        _("on") : _("off"));
				g_ptr_array_add (nmc->output_data, arr);

				print_data (nmc);  /* Print all data */
				was_output = TRUE;
			}
		}
#if WITH_WIMAX
		else if (NM_IS_DEVICE_WIMAX (device)) {
			/* WIMAX-PROPERTIES */
			if (!strcasecmp (nmc_fields_dev_show_sections[section_idx].name, nmc_fields_dev_show_sections[5].name)) {
				char *cfreq = NULL, *rssi = NULL, *cinr = NULL, *txpow = NULL;
				guint tmp_uint;
				gint tmp_int;

				/* Field names */
				tmpl = nmc_fields_dev_show_wimax_prop;
				tmpl_len = sizeof (nmc_fields_dev_show_wimax_prop);
				nmc->print_fields.indices = parse_output_fields (section_fld ? section_fld : NMC_FIELDS_DEV_SHOW_WIMAX_PROP_ALL,
				                                                 tmpl, FALSE, NULL, NULL);
				arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (nmc->output_data, arr);

				/* Center frequency */
				tmp_uint = nm_device_wimax_get_center_frequency (NM_DEVICE_WIMAX (device));
				if (tmp_uint)
					cfreq = g_strdup_printf ("%'.1f MHz", (double) tmp_uint / 1000.0);

				/* RSSI */
				tmp_int = nm_device_wimax_get_rssi (NM_DEVICE_WIMAX (device));
				if (tmp_int)
					rssi = g_strdup_printf ("%d dBm", tmp_int);

				/* CINR */
				tmp_int = nm_device_wimax_get_cinr (NM_DEVICE_WIMAX (device));
				if (tmp_int)
					cinr = g_strdup_printf ("%d dB", tmp_int);

				/* TX Power */
				tmp_int = nm_device_wimax_get_tx_power (NM_DEVICE_WIMAX (device));
				if (tmp_int)
					txpow = g_strdup_printf ("%'.2f dBm", (float) tmp_int / 2.0);

				arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
				set_val_strc (arr, 0, nmc_fields_dev_show_sections[5].name);  /* "WIMAX-PROPERTIES" */
				set_val_str  (arr, 1, cfreq);
				set_val_str  (arr, 2, rssi);
				set_val_str  (arr, 3, cinr);
				set_val_str  (arr, 4, txpow);
				set_val_strc (arr, 5, nm_device_wimax_get_bsid (NM_DEVICE_WIMAX (device)));
				g_ptr_array_add (nmc->output_data, arr);

				print_data (nmc);  /* Print all data */
				was_output = TRUE;
			}

			/* section NSP */
			if (!strcasecmp (nmc_fields_dev_show_sections[section_idx].name, nmc_fields_dev_show_sections[6].name)) {
				const GPtrArray *nsps;
				int g, idx = 1;

				tmpl = nmc_fields_dev_wimax_list;
				tmpl_len = sizeof (nmc_fields_dev_wimax_list);
				nmc->print_fields.indices = parse_output_fields (section_fld ? section_fld : NMC_FIELDS_DEV_WIMAX_LIST_FOR_DEV_LIST,
				                                                 tmpl, FALSE, NULL, NULL);
				arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (nmc->output_data, arr);

				nsps = nm_device_wimax_get_nsps (NM_DEVICE_WIMAX (device));
				for (g = 0; nsps && g < nsps->len; g++) {
					NMWimaxNsp *nsp = g_ptr_array_index (nsps, g);

					fill_output_wimax_nsp (nsp, nmc, device, idx++, NMC_OF_FLAG_SECTION_PREFIX);
				}
				print_data (nmc);  /* Print all data */
				was_output = TRUE;
			}
		}
#endif

		/* IP configuration info */
		cfg4 = nm_device_get_ip4_config (device);
		cfg6 = nm_device_get_ip6_config (device);
		dhcp4 = nm_device_get_dhcp4_config (device);
		dhcp6 = nm_device_get_dhcp6_config (device);

		/* IP4 */
		if (cfg4 && !strcasecmp (nmc_fields_dev_show_sections[section_idx].name, nmc_fields_dev_show_sections[7].name))
			was_output = print_ip4_config (cfg4, nmc, nmc_fields_dev_show_sections[7].name, section_fld);

		/* DHCP4 */
		if (dhcp4 && !strcasecmp (nmc_fields_dev_show_sections[section_idx].name, nmc_fields_dev_show_sections[8].name))
			was_output = print_dhcp4_config (dhcp4, nmc, nmc_fields_dev_show_sections[8].name, section_fld);

		/* IP6 */
		if (cfg6 && !strcasecmp (nmc_fields_dev_show_sections[section_idx].name, nmc_fields_dev_show_sections[9].name))
			was_output = print_ip6_config (cfg6, nmc, nmc_fields_dev_show_sections[9].name, section_fld);

		/* DHCP6 */
		if (dhcp6 && !strcasecmp (nmc_fields_dev_show_sections[section_idx].name, nmc_fields_dev_show_sections[10].name))
			was_output = print_dhcp6_config (dhcp6, nmc, nmc_fields_dev_show_sections[10].name, section_fld);

		/* Bond-specific information */
		if ((NM_IS_DEVICE_BOND (device))) {
			if (!strcasecmp (nmc_fields_dev_show_sections[section_idx].name, nmc_fields_dev_show_sections[11].name)) {
				const GPtrArray *slaves;
				GString *bond_slaves_str;
				int idx;

				bond_slaves_str = g_string_new (NULL);
				slaves = nm_device_bond_get_slaves (NM_DEVICE_BOND (device));
				for (idx = 0; slaves && idx < slaves->len; idx++) {
					NMDevice *slave = g_ptr_array_index (slaves, idx);
					const char *iface = nm_device_get_iface (slave);

					if (iface) {
						g_string_append (bond_slaves_str, iface);
						g_string_append_c (bond_slaves_str, ' ');
					}
				}
				if (bond_slaves_str->len > 0)
					g_string_truncate (bond_slaves_str, bond_slaves_str->len-1);  /* Chop off last space */

				tmpl = nmc_fields_dev_show_bond_prop;
				tmpl_len = sizeof (nmc_fields_dev_show_bond_prop);
				nmc->print_fields.indices = parse_output_fields (section_fld ? section_fld : NMC_FIELDS_DEV_SHOW_BOND_PROP_ALL,
				                                                 tmpl, FALSE, NULL, NULL);
				arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (nmc->output_data, arr);

				arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
				set_val_strc (arr, 0, nmc_fields_dev_show_sections[11].name);  /* "BOND" */
				set_val_str  (arr, 1, bond_slaves_str->str);
				g_ptr_array_add (nmc->output_data, arr);

				print_data (nmc);  /* Print all data */

				g_string_free (bond_slaves_str, FALSE);
				was_output = TRUE;
			}
		}

		/* VLAN-specific information */
		if ((NM_IS_DEVICE_VLAN (device))) {
			if (!strcasecmp (nmc_fields_dev_show_sections[section_idx].name, nmc_fields_dev_show_sections[12].name)) {
				char * vlan_id_str = g_strdup_printf ("%u", nm_device_vlan_get_vlan_id (NM_DEVICE_VLAN (device)));

				tmpl = nmc_fields_dev_show_vlan_prop;
				tmpl_len = sizeof (nmc_fields_dev_show_vlan_prop);
				nmc->print_fields.indices = parse_output_fields (section_fld ? section_fld : NMC_FIELDS_DEV_SHOW_VLAN_PROP_ALL,
				                                                 tmpl, FALSE, NULL, NULL);
				arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (nmc->output_data, arr);

				arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
				set_val_strc (arr, 0, nmc_fields_dev_show_sections[12].name);  /* "VLAN" */
				set_val_str  (arr, 1, vlan_id_str);
				g_ptr_array_add (nmc->output_data, arr);

				print_data (nmc);  /* Print all data */

				was_output = TRUE;
			}
		}

		/* section CONNECTIONS */
		if (!strcasecmp (nmc_fields_dev_show_sections[section_idx].name, nmc_fields_dev_show_sections[13].name)) {
			const GPtrArray *avail_cons;
			GString *ac_paths_str;
			char **ac_arr = NULL;
			int i;

			tmpl = nmc_fields_dev_show_connections;
			tmpl_len = sizeof (nmc_fields_dev_show_connections);
			nmc->print_fields.indices = parse_output_fields (section_fld ? section_fld : NMC_FIELDS_DEV_SHOW_CONNECTIONS_ALL,
			                                                 tmpl, FALSE, NULL, NULL);
			arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
			g_ptr_array_add (nmc->output_data, arr);

			/* available-connections */
			avail_cons = nm_device_get_available_connections (device);
			ac_paths_str = g_string_new (NULL);
			if (avail_cons && avail_cons->len) {
				ac_arr = g_new (char *, avail_cons->len + 1);
				ac_arr[avail_cons->len] = NULL;
			}
			for (i = 0; avail_cons && (i < avail_cons->len); i++) {
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

			arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
			set_val_strc (arr, 0, nmc_fields_dev_show_sections[13].name);  /* "CONNECTIONS" */
			set_val_str  (arr, 1, ac_paths_str->str);
			set_val_arr  (arr, 2, (ac_arr));
			g_ptr_array_add (nmc->output_data, arr);

			print_data (nmc);  /* Print all data */

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

static void
fill_output_device_status (NMDevice *device, NmCli *nmc)
{
	NMActiveConnection *ac;
	NmcOutputField *arr = nmc_dup_fields_array (nmc_fields_dev_status,
	                                            sizeof (nmc_fields_dev_status),
	                                            0);

	ac = nm_device_get_active_connection (device);

	set_val_strc (arr, 0, nm_device_get_iface (device));
	set_val_strc (arr, 1, nm_device_get_type_description (device));
	set_val_strc (arr, 2, nmc_device_state_to_string (nm_device_get_state (device)));
	set_val_strc (arr, 3, nm_object_get_path (NM_OBJECT (device)));
	set_val_strc (arr, 4, get_active_connection_id (device));
	set_val_strc (arr, 5, ac ? nm_active_connection_get_uuid (ac) : NULL);
	set_val_strc (arr, 6, ac ? nm_object_get_path (NM_OBJECT (ac)) : NULL);

	g_ptr_array_add (nmc->output_data, arr);
}

static NMCResultCode
do_devices_status (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;
	NMDevice **devices;
	int i;
	char *fields_str;
	char *fields_all =    NMC_FIELDS_DEV_STATUS_ALL;
	char *fields_common = NMC_FIELDS_DEV_STATUS_COMMON;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	while (argc > 0) {
		fprintf (stderr, _("Unknown parameter: %s\n"), *argv);
		argc--;
		argv++;
	}

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else
		fields_str = nmc->required_fields;

	tmpl = nmc_fields_dev_status;
	tmpl_len = sizeof (nmc_fields_dev_status);
	nmc->print_fields.indices = parse_output_fields (fields_str, tmpl, FALSE, NULL, &error);

	if (error) {
		g_string_printf (nmc->return_text, _("Error: 'device status': %s"), error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}

	nmc->get_client (nmc);

	if (!nm_client_get_manager_running (nmc->client)) {
		g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
		nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		goto error;
	}

	if (!nmc_versions_match (nmc))
		goto error;

	/* Add headers */
	nmc->print_fields.header_name = _("Status of devices");
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	devices = get_devices_sorted (nmc->client);
	for (i = 0; devices[i]; i++)
		fill_output_device_status (devices[i], nmc);

	/* Now print all data */
	print_data (nmc);

	g_free (devices);

	return NMC_RESULT_SUCCESS;

error:
	return nmc->return_value;
}

static NMCResultCode
do_devices_show (NmCli *nmc, int argc, char **argv)
{
	NMDevice **devices = NULL;
	NMDevice *device = NULL;
	const char *ifname = NULL;
	int i;
	gboolean ret;

	if (argc == 1)
		ifname = *argv;
	else if (argc > 1) {
		g_string_printf (nmc->return_text, _("Error: invalid extra argument '%s'."), *(argv+1));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}

	nmc->get_client (nmc);

	if (!nm_client_get_manager_running (nmc->client)) {
		g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
		nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		goto error;
	}

	if (!nmc_versions_match (nmc))
		goto error;

	devices = get_devices_sorted (nmc->client);

	if (ifname) {
		/* Interface specified; show details only for the device */
		for (i = 0; devices[i]; i++) {
			NMDevice *candidate = devices[i];
			const char *dev_iface = nm_device_get_iface (candidate);

			if (!g_strcmp0 (dev_iface, ifname))
				device = candidate;
		}
		if (!device) {
			g_string_printf (nmc->return_text, _("Error: Device '%s' not found."), ifname);
			nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
			goto error;
		}
		show_device_info (device, nmc);
	} else {
		/* Show details for all devices */
		for (i = 0; devices[i]; i++) {
			nmc_empty_output_fields (nmc);
			ret = show_device_info (devices[i], nmc);
			if (!ret)
				break;
			if (devices[i + 1])
				printf ("\n"); /* Empty line */
		}
	}

error:
	g_free (devices);
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

static void
connected_state_cb (NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
	NMActiveConnection *active = (NMActiveConnection *) user_data;
	NMDeviceState state;

	state = nm_device_get_state (device);

	if (state == NM_DEVICE_STATE_ACTIVATED) {
		nmc_terminal_erase_line ();
		printf (_("Device '%s' successfully activated with '%s'.\n"),
		        nm_device_get_iface (device),
		        nm_active_connection_get_uuid (active));
		quit ();
	}
}

static void
connect_device_cb (NMClient *client, NMActiveConnection *active, GError *error, gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;
	const GPtrArray *devices;
	NMDevice *device;
	NMDeviceState state;

	if (error) {
		g_string_printf (nmc->return_text, _("Error: Device activation failed: %s"),
		                 error->message ? error->message : _("(unknown)"));
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		quit ();
	} else {
		g_assert (active);
		devices = nm_active_connection_get_devices (active);
		if (!devices || devices->len == 0) {
			g_string_printf (nmc->return_text, _("Error: Device activation failed: device was disconnected"));
			nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
			quit ();
			return;
		}

		device = g_ptr_array_index (devices, 0);
		state = nm_device_get_state (device);

		if (nmc->nowait_flag || state == NM_DEVICE_STATE_ACTIVATED) {
			/* Don't want to wait or device already activated */
			if (state == NM_DEVICE_STATE_ACTIVATED && nmc->print_output == NMC_PRINT_PRETTY) {
				nmc_terminal_erase_line ();
				printf (_("Device '%s' has been connected.\n"), nm_device_get_iface (device));
			}
			quit ();
		} else {
			g_signal_connect (device, "notify::state", G_CALLBACK (connected_state_cb), active);
			/* Start timer not to loop forever if "notify::state" signal is not issued */
			g_timeout_add_seconds (nmc->timeout, timeout_cb, nmc);
		}
	}
}

static NMCResultCode
do_device_connect (NmCli *nmc, int argc, char **argv)
{
	NMDevice **devices;
	NMDevice *device = NULL;
	const char *ifname = NULL;
	char *ifname_ask = NULL;
	int i;

	/* Set default timeout for connect operation. */
	if (nmc->timeout == -1)
		nmc->timeout = 90;

	if (argc == 0) {
		if (nmc->ask)
			ifname = ifname_ask = nmc_readline (PROMPT_INTERFACE);

		if (!ifname_ask) {
			g_string_printf (nmc->return_text, _("Error: No interface specified."));
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto error;
		}
	} else {
		ifname = *argv;
	}

	if (!ifname) {
		g_string_printf (nmc->return_text, _("Error: No interface specified."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}

	if (next_arg (&argc, &argv) == 0) {
		g_string_printf (nmc->return_text, _("Error: extra argument not allowed: '%s'."), *argv);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}

	nmc->get_client (nmc);
	if (!nm_client_get_manager_running (nmc->client)) {
		g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
		nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		goto error;
	}

	if (!nmc_versions_match (nmc))
		goto error;

	devices = get_devices_sorted (nmc->client);
	for (i = 0; devices[i]; i++) {
		NMDevice *candidate = devices[i];
		const char *dev_iface = nm_device_get_iface (candidate);

		if (!g_strcmp0 (dev_iface, ifname))
			device = candidate;
	}
	g_free (devices);

	if (!device) {
		g_string_printf (nmc->return_text, _("Error: Device '%s' not found."), ifname);
		nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
		goto error;
	}

	/*
	 * Use nowait_flag instead of should_wait, because exiting has to be postponed
	 * till connect_device_cb() is called, giving NM time to check our permissions.
	 */
	nmc->nowait_flag = (nmc->timeout == 0);
	nmc->should_wait = TRUE;
	nm_client_activate_connection (nmc->client,
	                               NULL,  /* let NM find a connection automatically */
	                               device,
	                               NULL,
	                               connect_device_cb,
	                               nmc);

	/* Start progress indication */
	if (nmc->print_output == NMC_PRINT_PRETTY)
		progress_id = g_timeout_add (120, progress_cb, device);

error:
	g_free (ifname_ask);

	return nmc->return_value;
}

static void
disconnect_state_cb (NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;
	NMDeviceState state;

	state = nm_device_get_state (device);

	if (state == NM_DEVICE_STATE_DISCONNECTED) {
		g_string_printf (nmc->return_text, _("Success: Device '%s' successfully disconnected."), nm_device_get_iface (device));
		quit ();
	}
}

static void
disconnect_device_cb (NMDevice *device, GError *error, gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;
	NMDeviceState state;

	if (error) {
		g_string_printf (nmc->return_text, _("Error: Device '%s' (%s) disconnecting failed: %s"),
		                 nm_device_get_iface (device),
		                 nm_object_get_path (NM_OBJECT (device)),
		                 error->message ? error->message : _("(unknown)"));
		nmc->return_value = NMC_RESULT_ERROR_DEV_DISCONNECT;
		quit ();
	} else {
		state = nm_device_get_state (device);

		if (nmc->nowait_flag || state == NM_DEVICE_STATE_DISCONNECTED) {
			/* Don't want to wait or device already disconnected */
			if (state == NM_DEVICE_STATE_DISCONNECTED) {
				if (nmc->print_output == NMC_PRINT_PRETTY)
					nmc_terminal_erase_line ();
				printf (_("Device '%s' has been disconnected.\n"), nm_device_get_iface (device));
			}
			quit ();
		} else {
			g_signal_connect (device, "notify::state", G_CALLBACK (disconnect_state_cb), nmc);
			/* Start timer not to loop forever if "notify::state" signal is not issued */
			g_timeout_add_seconds (nmc->timeout, timeout_cb, nmc);
		}

	}
}

static NMCResultCode
do_device_disconnect (NmCli *nmc, int argc, char **argv)
{
	NMDevice **devices;
	NMDevice *device = NULL;
	const char *ifname = NULL;
	char *ifname_ask = NULL;
	int i;

	/* Set default timeout for disconnect operation. */
	if (nmc->timeout == -1)
		nmc->timeout = 10;

	if (argc == 0) {
		if (nmc->ask)
			ifname = ifname_ask = nmc_readline (PROMPT_INTERFACE);

		if (!ifname_ask) {
			g_string_printf (nmc->return_text, _("Error: No interface specified."));
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto error;
		}
	} else {
		ifname = *argv;
	}

	if (!ifname) {
		g_string_printf (nmc->return_text, _("Error: No interface specified."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}

	if (next_arg (&argc, &argv) == 0) {
		g_string_printf (nmc->return_text, _("Error: extra argument not allowed: '%s'."), *argv);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}

	nmc->get_client (nmc);
	if (!nm_client_get_manager_running (nmc->client)) {
		g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
		nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		goto error;
	}

	if (!nmc_versions_match (nmc))
		goto error;

	devices = get_devices_sorted (nmc->client);
	for (i = 0; devices[i]; i++) {
		NMDevice *candidate = devices[i];
		const char *dev_iface = nm_device_get_iface (candidate);

		if (!g_strcmp0 (dev_iface, ifname))
			device = candidate;
	}
	g_free (devices);

	if (!device) {
		g_string_printf (nmc->return_text, _("Error: Device '%s' not found."), ifname);
		nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
		goto error;
	}

	/*
	 * Use nowait_flag instead of should_wait, because exiting has to be postponed
	 * till disconnect_device_cb() is called, giving NM time to check our permissions.
	 */
	nmc->nowait_flag = (nmc->timeout == 0);
	nmc->should_wait = TRUE;
	nm_device_disconnect (device, disconnect_device_cb, nmc);

	/* Start progress indication */
	if (nmc->print_output == NMC_PRINT_PRETTY)
		progress_id = g_timeout_add (120, progress_cb, device);

error:
	return nmc->return_value;
}

static void
show_acces_point_info (NMDevice *device, NmCli *nmc)
{
	NMAccessPoint *active_ap = NULL;
	const char *active_bssid = NULL;
	const GPtrArray *aps;
	APInfo *info;
	NmcOutputField *arr;

	if (nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED) {
		active_ap = nm_device_wifi_get_active_access_point (NM_DEVICE_WIFI (device));
		active_bssid = active_ap ? nm_access_point_get_bssid (active_ap) : NULL;
	}

	arr = nmc_dup_fields_array (nmc_fields_dev_wifi_list, sizeof (nmc_fields_dev_wifi_list),
	                            NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	info = g_malloc0 (sizeof (APInfo));
	info->nmc = nmc;
	info->index = 1;
	info->output_flags = 0;
	info->active_bssid = active_bssid;
	info->device = nm_device_get_iface (device);
	aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (device));
	if (aps && aps->len)
		g_ptr_array_foreach ((GPtrArray *) aps, fill_output_access_point, (gpointer) info);

	print_data (nmc);  /* Print all data */
	nmc_empty_output_fields (nmc);
	g_free (info);
}

static NMCResultCode
do_device_wifi_list (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;
	NMDevice *device = NULL;
	NMAccessPoint *ap = NULL;
	const char *ifname = NULL;
	const char *bssid_user = NULL;
	NMDevice **devices = NULL;
	const GPtrArray *aps;
	APInfo *info;
	int i, j;
	char *fields_str;
	char *fields_all =    NMC_FIELDS_DEV_WIFI_LIST_ALL;
	char *fields_common = NMC_FIELDS_DEV_WIFI_LIST_COMMON;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;
	const char *base_hdr = _("Wi-Fi scan list");

	while (argc > 0) {
		if (strcmp (*argv, "ifname") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			ifname = *argv;
		} else if (strcmp (*argv, "bssid") == 0 || strcmp (*argv, "hwaddr") == 0) {
			/* hwaddr is deprecated and will be removed later */
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			bssid_user = *argv;
		} else {
			fprintf (stderr, _("Unknown parameter: %s\n"), *argv);
		}

		argc--;
		argv++;
	}

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else
		fields_str = nmc->required_fields;

	tmpl = nmc_fields_dev_wifi_list;
	tmpl_len = sizeof (nmc_fields_dev_wifi_list);
	nmc->print_fields.indices = parse_output_fields (fields_str, tmpl, FALSE, NULL, &error);

	if (error) {
		g_string_printf (nmc->return_text, _("Error: 'device wifi': %s"), error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}

	nmc->get_client (nmc);

	if (!nm_client_get_manager_running (nmc->client)) {
		g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
		nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		goto error;
	}

	if (!nmc_versions_match (nmc))
		goto error;

	devices = get_devices_sorted (nmc->client);
	if (ifname) {
		/* Device specified - list only APs of this interface */
		for (i = 0; devices[i]; i++) {
			NMDevice *candidate = devices[i];
			const char *dev_iface = nm_device_get_iface (candidate);

			if (!g_strcmp0 (dev_iface, ifname)) {
				device = candidate;
				break;
			}
		}
		if (!device) {
			g_string_printf (nmc->return_text, _("Error: Device '%s' not found."), ifname);
			nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
			goto error;
		}

		/* Main header name */
		nmc->print_fields.header_name = (char *) construct_header_name (base_hdr, ifname);

		if (NM_IS_DEVICE_WIFI (device)) {
			if (bssid_user) {
				/* Specific AP requested - list only that */
				aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (device));
				for (j = 0; aps && (j < aps->len); j++) {
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
					nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
					goto error;
				}
				/* Add headers (field names) */
				arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (nmc->output_data, arr);

				info = g_malloc0 (sizeof (APInfo));
				info->nmc = nmc;
				info->index = 1;
				info->output_flags = 0;
				info->active_bssid = NULL;
				info->device = nm_device_get_iface (device);

				fill_output_access_point (ap, info);

				print_data (nmc);  /* Print all data */
				g_free (info);
			} else {
				show_acces_point_info (device, nmc);
			}
		} else {
			g_string_printf (nmc->return_text, _("Error: Device '%s' is not a Wi-Fi device."), ifname);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			goto error;
		}
	} else {
		/* List APs for all devices */
		if (bssid_user) {
			/* Specific AP requested - list only that */
			for (i = 0; devices[i]; i++) {
				NMDevice *dev = devices[i];

				if (!NM_IS_DEVICE_WIFI (dev))
					continue;

				/* Main header name */
				nmc->print_fields.header_name = (char *) construct_header_name (base_hdr, nm_device_get_iface (dev));

				arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (nmc->output_data, arr);

				aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (dev));
				for (j = 0; aps && (j < aps->len); j++) {
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
				print_data (nmc);  /* Print all data */
				nmc_empty_output_fields (nmc);
			}
			if (!ap) {
				g_string_printf (nmc->return_text, _("Error: Access point with bssid '%s' not found."),
				                 bssid_user);
				nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
				goto error;
			}
		} else {
			for (i = 0; devices[i]; i++) {
				NMDevice *dev = devices[i];

				/* Main header name */
				nmc->print_fields.header_name = (char *) construct_header_name (base_hdr,
				                                                                nm_device_get_iface (dev));
				if (NM_IS_DEVICE_WIFI (dev))
					show_acces_point_info (dev, nmc);
			}
		}
	}

error:
	g_free (devices);
	return nmc->return_value;
}

static void
monitor_device_state_cb (NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;
	NMDeviceState state;
	NMDeviceStateReason reason;

	state = nm_device_get_state_reason (device, &reason);

	if (state == NM_DEVICE_STATE_ACTIVATED) {
		NMActiveConnection *active = nm_device_get_active_connection (device);

		if (nmc->print_output == NMC_PRINT_PRETTY)
			nmc_terminal_erase_line ();
		printf (_("Connection with UUID '%s' created and activated on device '%s'\n"),
		        nm_active_connection_get_uuid (active), nm_device_get_iface (device));
		quit ();
	} else if (state == NM_DEVICE_STATE_FAILED) {
		g_string_printf (nmc->return_text, _("Error: Connection activation failed: (%d) %s."),
		                 reason, nmc_device_reason_to_string (reason));
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		quit ();
	}
}

typedef struct {
	NmCli *nmc;
	NMDevice *device;
} AddAndActivateInfo;

static void
add_and_activate_cb (NMClient *client,
                     NMActiveConnection *active,
                     const char *connection_path,
                     GError *error,
                     gpointer user_data)
{
	AddAndActivateInfo *info = (AddAndActivateInfo *) user_data;
	NmCli *nmc = info->nmc;
	NMDevice *device = info->device;
	NMActiveConnectionState state;

        if (error) {
		g_string_printf (nmc->return_text, _("Error: Failed to add/activate new connection: (%d) %s"),
		                 error->code, error->message);
		nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
		quit ();
	} else {
		state = nm_active_connection_get_state (active);

		if (state == NM_ACTIVE_CONNECTION_STATE_UNKNOWN) {
			g_string_printf (nmc->return_text, _("Error: Failed to add/activate new connection: Unknown error"));
			nmc->return_value = NMC_RESULT_ERROR_CON_ACTIVATION;
			quit ();
		}

		if (nmc->nowait_flag || state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
			/* User doesn't want to wait or already activated */
			if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
				if (nmc->print_output == NMC_PRINT_PRETTY)
					nmc_terminal_erase_line ();
				printf (_("Connection with UUID '%s' created and activated on device '%s'\n"),
				        nm_active_connection_get_uuid (active), nm_device_get_iface (device));
			}
			quit ();
		} else {
			g_signal_connect (device, "notify::state", G_CALLBACK (monitor_device_state_cb), nmc);
			g_timeout_add_seconds (nmc->timeout, timeout_cb, nmc);  /* Exit if timeout expires */

			if (nmc->print_output == NMC_PRINT_PRETTY)
				progress_id = g_timeout_add (120, progress_cb, device);
		}
	}

	g_free (info);
}

/*
 * Find a Wi-Fi device with 'iface' in 'devices' array. If 'iface' is NULL,
 * the first Wi-Fi device is returned. 'idx' parameter is updated to the point
 * where the function finished so that the function can be called repeatedly
 * to get next matching device.
 * Returns: found device or NULL
 */
static NMDevice *
find_wifi_device_by_iface (const GPtrArray *devices, const char *iface, int *idx)
{
	NMDevice *device = NULL;
	int i;

	for (i = *idx; devices && (i < devices->len); i++) {
		NMDevice *candidate = g_ptr_array_index (devices, i);
		const char *dev_iface = nm_device_get_iface (candidate);

		if (!NM_IS_DEVICE_WIFI (candidate))
			continue;

		if (iface) {
			/* If a iface was specified then use it. */
			if (g_strcmp0 (dev_iface, iface) == 0) {
				device = candidate;
				break;
			}
		} else {
			/* Else return the first Wi-Fi device. */
			device = candidate;
			break;
		}
	}

	*idx = i + 1;
	return device;
}

/*
 * Find AP on 'device' according to 'bssid' or 'ssid' parameter.
 * Returns: found AP or NULL
 */
static NMAccessPoint *
find_ap_on_device (NMDevice *device, GByteArray *bssid, const char *ssid)
{
	const GPtrArray *aps;
	NMAccessPoint *ap = NULL;
	int i;

	g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), NULL);
	g_return_val_if_fail ((bssid && !ssid) || (!bssid && ssid), NULL);

	aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (device));
	for (i = 0; aps && (i < aps->len); i++) {
		NMAccessPoint *candidate_ap = g_ptr_array_index (aps, i);

		if (ssid) {
			/* Parameter is SSID */
			const GByteArray *candidate_ssid;

			candidate_ssid = nm_access_point_get_ssid (candidate_ap);
			if (candidate_ssid) {
				char *ssid_tmp = nm_utils_ssid_to_utf8 (candidate_ssid);

				/* Compare SSIDs */
				if (strcmp (ssid, ssid_tmp) == 0) {
					ap = candidate_ap;
					g_free (ssid_tmp);
					break;
				}
				g_free (ssid_tmp);
			}
		} else if (bssid) {
			/* Parameter is BSSID */
			const char *candidate_bssid = nm_access_point_get_bssid (candidate_ap);
			char *bssid_up = nm_utils_hwaddr_ntoa (bssid->data, ARPHRD_ETHER);

			/* Compare BSSIDs */
			if (strcmp (bssid_up, candidate_bssid) == 0) {
				ap = candidate_ap;
				g_free (bssid_up);
				break;
			}
			g_free (bssid_up);
		}
	}

	return ap;
}

static NMCResultCode
do_device_wifi_connect_network (NmCli *nmc, int argc, char **argv)
{
	NMDevice *device = NULL;
	NMAccessPoint *ap = NULL;
	NM80211ApFlags ap_flags;
	NM80211ApSecurityFlags ap_wpa_flags;
	NM80211ApSecurityFlags ap_rsn_flags;
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
	gboolean wep_passphrase = FALSE;
	GByteArray *bssid1_arr = NULL;
	GByteArray *bssid2_arr = NULL;
	const GPtrArray *devices;
	int devices_idx;
	char *ssid_ask = NULL;
	char *passwd_ask = NULL;

	/* Set default timeout waiting for operation completion. */
	if (nmc->timeout == -1)
		nmc->timeout = 90;

	/* Get the first compulsory argument (SSID or BSSID) */
	if (argc > 0) {
		param_user = *argv;
		bssid1_arr = nm_utils_hwaddr_atoba (param_user, ARPHRD_ETHER);

		argc--;
		argv++;
	} else {
		if (nmc->ask) {
			ssid_ask = nmc_readline (_("SSID or BSSID: "));
			param_user = ssid_ask ? ssid_ask : "";
			bssid1_arr = nm_utils_hwaddr_atoba (param_user, ARPHRD_ETHER);
		}
		if (!ssid_ask) {
			g_string_printf (nmc->return_text, _("Error: SSID or BSSID are missing."));
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			goto error;
		}
	}

	/* Get the rest of the parameters */
	while (argc > 0) {
		if (strcmp (*argv, "ifname") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			ifname = *argv;
		} else if (strcmp (*argv, "bssid") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			bssid = *argv;
			bssid2_arr = nm_utils_hwaddr_atoba (bssid, ARPHRD_ETHER);
			if (!bssid2_arr) {
				g_string_printf (nmc->return_text, _("Error: bssid argument value '%s' is not a valid BSSID."),
				                 bssid);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
		} else if (strcmp (*argv, "password") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			password = *argv;
		} else if (strcmp (*argv, "wep-key-type") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			if (strcmp (*argv, "key") == 0)
				wep_passphrase = FALSE;
			else if (strcmp (*argv, "phrase") == 0)
				wep_passphrase = TRUE;
			else {
				g_string_printf (nmc->return_text,
				                 _("Error: wep-key-type argument value '%s' is invalid, use 'key' or 'phrase'."),
				                 *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
		} else if (strcmp (*argv, "name") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			con_name = *argv;
		} else if (strcmp (*argv, "private") == 0) {
			GError *err_tmp = NULL;
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			if (!nmc_string_to_bool (*argv, &private, &err_tmp)) {
				g_string_printf (nmc->return_text, _("Error: %s: %s."), *(argv-1), err_tmp->message);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				g_clear_error (&err_tmp);
				goto error;
			}
		} else {
			fprintf (stderr, _("Unknown parameter: %s\n"), *argv);
		}

		argc--;
		argv++;
	}

	/* Verify SSID/BSSID parameters */
	if (bssid1_arr && bssid2_arr && memcmp (bssid1_arr->data, bssid2_arr->data, ETH_ALEN)) {
		g_string_printf (nmc->return_text, _("Error: BSSID to connect to (%s) differs from bssid argument (%s)."),
		                 param_user, bssid);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}
	if (!bssid1_arr && strlen (param_user) > 32) {
		g_string_printf (nmc->return_text, _("Error: Parameter '%s' is neither SSID nor BSSID."), param_user);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}

	nmc->get_client (nmc);

	if (!nm_client_get_manager_running (nmc->client)) {
		g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
		nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		goto error;
	}

	if (!nmc_versions_match (nmc))
		goto error;

	devices = nm_client_get_devices (nmc->client);

	/* Find a device to activate the connection on */
	devices_idx = 0;
	device = find_wifi_device_by_iface (devices, ifname, &devices_idx);

	if (!device) {
		if (ifname)
			g_string_printf (nmc->return_text, _("Error: Device '%s' is not a Wi-Fi device."), ifname);
		else
			g_string_printf (nmc->return_text, _("Error: No Wi-Fi device found."));
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto error;
	}

	/* Find an AP to connect to */
	ap = find_ap_on_device (device, bssid1_arr, bssid1_arr ? NULL : param_user);
	if (!ap && !ifname) {
		/* AP not found. ifname was not specified, so try finding the AP on another device. */
		while ((device = find_wifi_device_by_iface (devices, NULL, &devices_idx)) != NULL) {
			ap = find_ap_on_device (device, bssid1_arr, bssid1_arr ? NULL : param_user);
			if (ap)
				break;
		}
	}

	if (!ap) {
		if (!bssid1_arr)
			g_string_printf (nmc->return_text, _("Error: No network with SSID '%s' found."), param_user);
		else
			g_string_printf (nmc->return_text, _("Error: No access point with BSSID '%s' found."), param_user);
		nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
		goto error;
	}

	/* If there are some connection data from user, create a connection and
	 * fill them into proper settings. */
	if (con_name || private || bssid2_arr || password)
		connection = nm_connection_new ();

	if (con_name || private) {
		s_con =  (NMSettingConnection *) nm_setting_connection_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_con));

		/* Set user provided connection name */
		if (con_name)
			g_object_set (s_con, NM_SETTING_CONNECTION_ID, con_name, NULL);

		/* Connection will only be visible to this user when '--private' is specified */
		if (private)
			nm_setting_connection_add_permission (s_con, "user", g_get_user_name (), NULL);
	}
	if (bssid2_arr) {
		s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wifi));

		/* 'bssid' parameter is used to restrict the conenction only to the BSSID */
		g_object_set (s_wifi, NM_SETTING_WIRELESS_BSSID, bssid2_arr, NULL);
	}

	/* handle password */
	ap_flags = nm_access_point_get_flags (ap);
	ap_wpa_flags = nm_access_point_get_wpa_flags (ap);
	ap_rsn_flags = nm_access_point_get_rsn_flags (ap);

	/* Set password for WEP or WPA-PSK. */
	if (ap_flags & NM_802_11_AP_FLAGS_PRIVACY) {
		/* Ask for missing password when one is expected and '--ask' is used */
		if (!password && nmc->ask)
			password = passwd_ask = nmc_readline (_("Password: "));

		if (password) {
			if (!connection)
				connection = nm_connection_new ();
			s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
			nm_connection_add_setting (connection, NM_SETTING (s_wsec));

			if (ap_wpa_flags == NM_802_11_AP_SEC_NONE && ap_rsn_flags == NM_802_11_AP_SEC_NONE) {
				/* WEP */
				nm_setting_wireless_security_set_wep_key (s_wsec, 0, password);
				g_object_set (G_OBJECT (s_wsec),
				              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE,
				              wep_passphrase ? NM_WEP_KEY_TYPE_PASSPHRASE: NM_WEP_KEY_TYPE_KEY,
				              NULL);
			} else if (   !(ap_wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
				   && !(ap_rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)) {
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
	nmc->should_wait = TRUE;

	info = g_malloc0 (sizeof (AddAndActivateInfo));
	info->nmc = nmc;
	info->device = device;

	nm_client_add_and_activate_connection (nmc->client,
	                                       connection,
	                                       device,
	                                       nm_object_get_path (NM_OBJECT (ap)),
	                                       add_and_activate_cb,
	                                       info);

error:
	if (bssid1_arr)
		g_byte_array_free (bssid1_arr, TRUE);
	if (bssid2_arr)
		g_byte_array_free (bssid2_arr, TRUE);
	g_free (ssid_ask);
	g_free (passwd_ask);

	return nmc->return_value;
}

static void
request_rescan_cb (NMDeviceWifi *device, GError *error, gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;

	if (error) {
		g_string_printf (nmc->return_text, _("Error: %s."),
		                 error->message ? error->message : _("unknown"));
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
	}
	quit ();
}

static NMCResultCode
do_device_wifi_rescan (NmCli *nmc, int argc, char **argv)
{
	NMDevice *device;
	const char *ifname = NULL;
	const GPtrArray *devices;
	int devices_idx;

	nmc->should_wait = TRUE;

	/* Get the parameters */
	if (argc > 0) {
		if (strcmp (*argv, "ifname") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
		}
		ifname = *argv;
	}

	/* Find Wi-Fi device to scan on. When no ifname is provided, the first Wi-Fi is used. */
	nmc->get_client (nmc);
	devices = nm_client_get_devices (nmc->client);
	devices_idx = 0;
	device = find_wifi_device_by_iface (devices, ifname, &devices_idx);

	if (!device) {
		if (ifname)
			g_string_printf (nmc->return_text, _("Error: Device '%s' is not a Wi-Fi device."), ifname);
		else
			g_string_printf (nmc->return_text, _("Error: No Wi-Fi device found."));
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto error;
	}

	nm_device_wifi_request_scan_simple (NM_DEVICE_WIFI (device), request_rescan_cb, nmc);

	return nmc->return_value;
error:
	nmc->should_wait = FALSE;
	return nmc->return_value;
}

static NMCResultCode
do_device_wifi (NmCli *nmc, int argc, char **argv)
{
	if (argc == 0)
		nmc->return_value = do_device_wifi_list (nmc, argc-1, argv+1);
	else if (argc > 0) {
		if (matches (*argv, "list") == 0) {
			nmc->return_value = do_device_wifi_list (nmc, argc-1, argv+1);
		} else if (matches (*argv, "connect") == 0) {
			nmc->return_value = do_device_wifi_connect_network (nmc, argc-1, argv+1);
		} else if (matches (*argv, "rescan") == 0) {
			nmc->return_value = do_device_wifi_rescan (nmc, argc-1, argv+1);
		} else {
			g_string_printf (nmc->return_text, _("Error: 'device wifi' command '%s' is not valid."), *argv);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		}
	}

	return nmc->return_value;
}

#if WITH_WIMAX
static void
show_nsp_info (NMDevice *device, NmCli *nmc)
{
	const GPtrArray *nsps;
	int i, idx = 1;
	NmcOutputField *arr;

	/* Add headers (field names) */
	arr = nmc_dup_fields_array (nmc_fields_dev_wimax_list, sizeof (nmc_fields_dev_wimax_list),
	                            NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	nsps = nm_device_wimax_get_nsps (NM_DEVICE_WIMAX (device));
	for (i = 0; nsps && i < nsps->len; i++) {
		NMWimaxNsp *nsp = g_ptr_array_index (nsps, i);

		fill_output_wimax_nsp (nsp, nmc, device, idx++, 0);
	}
	print_data (nmc);  /* Print all data */
	nmc_empty_output_fields (nmc);
}

static NMCResultCode
do_device_wimax_list (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;
	NMDevice *device = NULL;
	NMWimaxNsp *nsp = NULL;
	const char *ifname = NULL;
	const char *nsp_user = NULL;
	const GPtrArray *devices;
	const GPtrArray *nsps;
	int i, j;
	char *fields_str;
	char *fields_all =    NMC_FIELDS_DEV_WIMAX_LIST_ALL;
	char *fields_common = NMC_FIELDS_DEV_WIMAX_LIST_COMMON;
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;
	const char *base_hdr = _("WiMAX NSP list");

	while (argc > 0) {
		if (strcmp (*argv, "ifname") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			ifname = *argv;
		} else if (strcmp (*argv, "nsp") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *(argv-1));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			nsp_user = *argv;
		} else {
			fprintf (stderr, _("Unknown parameter: %s\n"), *argv);
		}

		argc--;
		argv++;
	}

	if (!nmc->required_fields || strcasecmp (nmc->required_fields, "common") == 0)
		fields_str = fields_common;
	else if (!nmc->required_fields || strcasecmp (nmc->required_fields, "all") == 0)
		fields_str = fields_all;
	else
		fields_str = nmc->required_fields;

	tmpl = nmc_fields_dev_wimax_list;
	tmpl_len = sizeof (nmc_fields_dev_wimax_list);
	nmc->print_fields.indices = parse_output_fields (fields_str, tmpl, FALSE, NULL, &error);

	if (error) {
		g_string_printf (nmc->return_text, _("Error: 'device wimax': %s"), error->message);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}

	nmc->get_client (nmc);

	if (!nm_client_get_manager_running (nmc->client)) {
		g_string_printf (nmc->return_text, _("Error: NetworkManager is not running."));
		nmc->return_value = NMC_RESULT_ERROR_NM_NOT_RUNNING;
		goto error;
	}

	if (!nmc_versions_match (nmc))
		goto error;

	devices = nm_client_get_devices (nmc->client);
	if (ifname) {
		/* Device specified - list only NSPs of this interface */
		for (i = 0; devices && (i < devices->len); i++) {
			NMDevice *candidate = g_ptr_array_index (devices, i);
			const char *dev_iface = nm_device_get_iface (candidate);

			if (!g_strcmp0 (dev_iface, ifname)) {
				device = candidate;
				break;
			}
		}

		if (!device) {
			g_string_printf (nmc->return_text, _("Error: Device '%s' not found."), ifname);
			nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
			goto error;
		}

		/* Main header name */
		nmc->print_fields.header_name = (char *) construct_header_name (base_hdr, ifname);

		if (NM_IS_DEVICE_WIMAX (device)) {
			if (nsp_user) {
				/* Specific NSP requested - list only that */
				nsps = nm_device_wimax_get_nsps (NM_DEVICE_WIMAX (device));
				for (j = 0, nsp = NULL; nsps && (j < nsps->len); j++) {
					NMWimaxNsp *candidate_nsp = g_ptr_array_index (nsps, j);
					const char *candidate_name = nm_wimax_nsp_get_name (candidate_nsp);
					char *nsp_up;

					nsp_up = g_ascii_strup (nsp_user, -1);
					if (!strcmp (nsp_up, candidate_name))
						nsp = candidate_nsp;
					g_free (nsp_up);
				}
				if (!nsp) {
					g_string_printf (nmc->return_text, _("Error: NSP with name '%s' not found."), nsp_user);
					nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
					goto error;
				}
				/* Add headers (field names) */
				arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (nmc->output_data, arr);
				fill_output_wimax_nsp (nsp, nmc, device, 1, 0);
				print_data (nmc);  /* Print all data */
			} else {
				show_nsp_info (device, nmc);
			}
		} else {
			g_string_printf (nmc->return_text, _("Error: Device '%s' is not a WiMAX device."), ifname);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			goto error;
		}
	} else {
		/* List NSPs for all devices */
		if (nsp_user) {
			/* Specific NSP requested - list only that */
			for (i = 0; devices && (i < devices->len); i++) {
				NMDevice *dev = g_ptr_array_index (devices, i);
				int idx = 1;

				if (!NM_IS_DEVICE_WIMAX (dev))
					continue;

				/* Main header name */
				nmc->print_fields.header_name = (char *) construct_header_name (base_hdr, nm_device_get_iface (dev));

				arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_MAIN_HEADER_ADD | NMC_OF_FLAG_FIELD_NAMES);
				g_ptr_array_add (nmc->output_data, arr);

				nsps = nm_device_wimax_get_nsps (NM_DEVICE_WIMAX (dev));
				for (j = 0, nsp = NULL; nsps && (j < nsps->len); j++) {
					NMWimaxNsp *candidate_nsp = g_ptr_array_index (nsps, j);
					const char *candidate_name = nm_wimax_nsp_get_name (candidate_nsp);
					char *nsp_up;

					nsp_up = g_ascii_strup (nsp_user, -1);
					if (!strcmp (nsp_up, candidate_name)) {
						nsp = candidate_nsp;
						fill_output_wimax_nsp (nsp, nmc, dev, idx, 0);
					}
					g_free (nsp_up);
				}
				print_data (nmc);  /* Print all data */
				nmc_empty_output_fields (nmc);
			}
			if (!nsp) {
				g_string_printf (nmc->return_text, _("Error: Access point with nsp '%s' not found."), nsp_user);
				nmc->return_value = NMC_RESULT_ERROR_NOT_FOUND;
				goto error;
			}
		} else {
			for (i = 0; devices && (i < devices->len); i++) {
				NMDevice *dev = g_ptr_array_index (devices, i);

				/* Main header name */
				nmc->print_fields.header_name = (char *) construct_header_name (base_hdr,
				                                                                nm_device_get_iface (dev));

				if (NM_IS_DEVICE_WIMAX (dev))
					show_nsp_info (dev, nmc);
			}
		}
	}

error:
	return nmc->return_value;
}

static NMCResultCode
do_device_wimax (NmCli *nmc, int argc, char **argv)
{
	if (argc == 0)
		nmc->return_value = do_device_wimax_list (nmc, argc-1, argv+1);
	else if (argc > 0) {
		if (matches (*argv, "list") == 0) {
			nmc->return_value = do_device_wimax_list (nmc, argc-1, argv+1);
		}
		else {
			g_string_printf (nmc->return_text, _("Error: 'device wimax' command '%s' is not valid."), *argv);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		}
	}

	return nmc->return_value;
}
#endif

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

/* Global variable defined in nmcli.c */
extern NmCli nm_cli;

static char *
gen_func_ifnames (const char *text, int state)
{
	int i, j = 0;
	const GPtrArray *devices;
	const char **ifnames;
	char *ret;

	nm_cli.get_client (&nm_cli);
	devices = nm_client_get_devices (nm_cli.client);
	if (!devices || devices->len < 1)
		return NULL;

	ifnames = g_new (const char *, devices->len + 1);
	for (i = 0; i < devices->len; i++) {
		NMDevice *dev = g_ptr_array_index (devices, i);
		const char *ifname = nm_device_get_iface (dev);
		ifnames[j++] = ifname;
	}
	ifnames[j] = NULL;

	ret = nmc_rl_gen_func_basic (text, state, ifnames);

	g_free (ifnames);
	return ret;
}

static char **
nmcli_device_tab_completion (const char *text, int start, int end)
{
	char **match_array = NULL;
	rl_compentry_func_t *generator_func = NULL;

	/* Disable readline's default filename completion */
	rl_attempted_completion_over = 1;

	/* Disable appending space after completion */
	rl_completion_append_character = '\0';

	if (!is_single_word (rl_line_buffer))
		return NULL;

	if (g_strcmp0 (rl_prompt, PROMPT_INTERFACE) == 0)
		generator_func = gen_func_ifnames;

	if (generator_func)
		match_array = rl_completion_matches (text, generator_func);

	return match_array;
}

NMCResultCode
do_devices (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;

	rl_attempted_completion_function = (rl_completion_func_t *) nmcli_device_tab_completion;

	if (argc == 0) {
		if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
			goto opt_error;
		nmc->return_value = do_devices_status (nmc, 0, NULL);
	}

	if (argc > 0) {
		if (nmc_arg_is_help (*argv)) {
			usage ();
			goto usage_exit;
		}
		else if (matches (*argv, "status") == 0) {
			if (nmc_arg_is_help (*(argv+1))) {
				usage_device_status ();
				goto usage_exit;
			}
			if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
				goto opt_error;
			nmc->return_value = do_devices_status (nmc, argc-1, argv+1);
		}
		else if (matches (*argv, "show") == 0) {
			if (nmc_arg_is_help (*(argv+1))) {
				usage_device_show ();
				goto usage_exit;
			}
			if (!nmc->mode_specified)
				nmc->multiline_output = TRUE;  /* multiline mode is default for 'device show' */
			nmc->return_value = do_devices_show (nmc, argc-1, argv+1);
		}
		else if (matches (*argv, "connect") == 0) {
			if (nmc_arg_is_help (*(argv+1))) {
				usage_device_connect ();
				goto usage_exit;
			}
			nmc->return_value = do_device_connect (nmc, argc-1, argv+1);
		}
		else if (matches (*argv, "disconnect") == 0) {
			if (nmc_arg_is_help (*(argv+1))) {
				usage_device_disconnect ();
				goto usage_exit;
			}
			nmc->return_value = do_device_disconnect (nmc, argc-1, argv+1);
		}
		else if (matches (*argv, "wifi") == 0) {
			if (nmc_arg_is_help (*(argv+1))) {
				usage_device_wifi ();
				goto usage_exit;
			}
			if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
				goto opt_error;
			nmc->return_value = do_device_wifi (nmc, argc-1, argv+1);
		}
#if WITH_WIMAX
		else if (matches (*argv, "wimax") == 0) {
			if (nmc_arg_is_help (*(argv+1))) {
				usage_device_wimax ();
				goto usage_exit;
			}
			if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
				goto opt_error;
			nmc->return_value = do_device_wimax (nmc, argc-1, argv+1);
		}
#endif
		else {
			usage ();
			g_string_printf (nmc->return_text, _("Error: 'dev' command '%s' is not valid."), *argv);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		}
	}

usage_exit:
	return nmc->return_value;

opt_error:
	g_string_printf (nmc->return_text, _("Error: %s."), error->message);
	nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
	g_error_free (error);
	return nmc->return_value;
}
