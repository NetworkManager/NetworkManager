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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/ether.h>

#include <glib.h>
#include <glib/gi18n.h>

#include <nm-client.h>
#include <nm-device.h>
#include <nm-device-ethernet.h>
#include <nm-device-wifi.h>
#include <nm-device-modem.h>
#include <nm-device-bt.h>
#include <nm-device-olpc-mesh.h>
#if WITH_WIMAX
#include <nm-device-wimax.h>
#endif
#include <nm-device-infiniband.h>
#include <nm-device-bond.h>
#include <nm-device-vlan.h>
#include <nm-utils.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-vpn-connection.h>
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
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


/* Available fields for 'dev status' */
static NmcOutputField nmc_fields_dev_status[] = {
	{"DEVICE",    N_("DEVICE"),      10, NULL, 0},  /* 0 */
	{"TYPE",      N_("TYPE"),        17, NULL, 0},  /* 1 */
	{"STATE",     N_("STATE"),       13, NULL, 0},  /* 2 */
	{"DBUS-PATH", N_("DBUS-PATH"),   43, NULL, 0},  /* 3 */
	{NULL,        NULL,               0, NULL, 0}
};
#define NMC_FIELDS_DEV_STATUS_ALL     "DEVICE,TYPE,STATE,DBUS-PATH"
#define NMC_FIELDS_DEV_STATUS_COMMON  "DEVICE,TYPE,STATE"


/* Available sections for 'dev list' */
static NmcOutputField nmc_fields_dev_list_sections[] = {
	{"GENERAL",           N_("GENERAL"),           0, NULL, 0},  /* 0 */
	{"CAPABILITIES",      N_("CAPABILITIES"),      0, NULL, 0},  /* 1 */
	{"WIFI-PROPERTIES",   N_("WIFI-PROPERTIES"),   0, NULL, 0},  /* 2 */
	{"AP",                N_("AP"),                0, NULL, 0},  /* 3 */
	{"WIRED-PROPERTIES",  N_("WIRED-PROPERTIES"),  0, NULL, 0},  /* 4 */
	{"WIMAX-PROPERTIES",  N_("WIMAX-PROPERTIES"),  0, NULL, 0},  /* 5 */
	{"NSP",               N_("NSP"),               0, NULL, 0},  /* 6 */
	{"IP4",               N_("IP4"),               0, NULL, 0},  /* 7 */
	{"DHCP4",             N_("DHCP4"),             0, NULL, 0},  /* 8 */
	{"IP6",               N_("IP6"),               0, NULL, 0},  /* 9 */
	{"DHCP6",             N_("DHCP6"),             0, NULL, 0},  /* 10 */
	{NULL,                NULL,                    0, NULL, 0}
};
#if WITH_WIMAX
#define NMC_FIELDS_DEV_LIST_SECTIONS_ALL     "GENERAL,CAPABILITIES,WIFI-PROPERTIES,AP,WIRED-PROPERTIES,WIMAX-PROPERTIES,NSP,IP4,DHCP4,IP6,DHCP6"
#define NMC_FIELDS_DEV_LIST_SECTIONS_COMMON  "GENERAL,CAPABILITIES,WIFI-PROPERTIES,AP,WIRED-PROPERTIES,WIMAX-PROPERTIES,NSP,IP4,DHCP4,IP6,DHCP6"
#else
#define NMC_FIELDS_DEV_LIST_SECTIONS_ALL     "GENERAL,CAPABILITIES,WIFI-PROPERTIES,AP,WIRED-PROPERTIES,IP4,DHCP4,IP6,DHCP6"
#define NMC_FIELDS_DEV_LIST_SECTIONS_COMMON  "GENERAL,CAPABILITIES,WIFI-PROPERTIES,AP,WIRED-PROPERTIES,IP4,DHCP4,IP6,DHCP6"
#endif

/* Available fields for 'dev list' - GENERAL part */
static NmcOutputField nmc_fields_dev_list_general[] = {
	{"NAME",              N_("NAME"),              10, NULL, 0},  /* 0 */
	{"DEVICE",            N_("DEVICE"),            10, NULL, 0},  /* 1 */
	{"TYPE",              N_("TYPE"),              17, NULL, 0},  /* 2 */
	{"VENDOR",            N_("VENDOR"),            20, NULL, 0},  /* 3 */
	{"PRODUCT",           N_("PRODUCT"),           50, NULL, 0},  /* 4 */
	{"DRIVER",            N_("DRIVER"),             9, NULL, 0},  /* 5 */
	{"HWADDR",            N_("HWADDR"),            19, NULL, 0},  /* 6 */
	{"STATE",             N_("STATE"),             14, NULL, 0},  /* 7 */
	{"REASON",            N_("REASON"),            25, NULL, 0},  /* 8 */
	{"UDI",               N_("UDI"),               64, NULL, 0},  /* 9 */
	{"IP-IFACE",          N_("IP-IFACE"),          10, NULL, 0},  /* 10 */
	{"NM-MANAGED",        N_("NM-MANAGED"),        15, NULL, 0},  /* 11 */
	{"FIRMWARE-MISSING",  N_("FIRMWARE-MISSING"),  18, NULL, 0},  /* 12 */
	{"CONNECTION",        N_("CONNECTION"),        51, NULL, 0},  /* 13 */
	{NULL, NULL, 0, NULL, 0}
};
#define NMC_FIELDS_DEV_LIST_GENERAL_ALL     "NAME,DEVICE,TYPE,VENDOR,PRODUCT,DRIVER,HWADDR,STATE,REASON,UDI,IP-IFACE,NM-MANAGED,FIRMWARE-MISSING,CONNECTION"
#define NMC_FIELDS_DEV_LIST_GENERAL_COMMON  "NAME,DEVICE,TYPE,VENDOR,PRODUCT,DRIVER,HWADDR,STATE"

/* Available fields for 'dev list' - CAPABILITIES part */
static NmcOutputField nmc_fields_dev_list_cap[] = {
	{"NAME",            N_("NAME"),            13, NULL, 0},  /* 0 */
	{"CARRIER-DETECT",  N_("CARRIER-DETECT"),  16, NULL, 0},  /* 1 */
	{"SPEED",           N_("SPEED"),           10, NULL, 0},  /* 2 */
	{NULL,              NULL,                   0, NULL, 0}
};
#define NMC_FIELDS_DEV_LIST_CAP_ALL     "NAME,CARRIER-DETECT,SPEED"
#define NMC_FIELDS_DEV_LIST_CAP_COMMON  "NAME,CARRIER-DETECT,SPEED"

/* Available fields for 'dev list' - wired properties part */
static NmcOutputField nmc_fields_dev_list_wired_prop[] = {
	{"NAME",            N_("NAME"),     18, NULL, 0},  /* 0 */
	{"CARRIER",         N_("CARRIER"),  10, NULL, 0},  /* 1 */
	{NULL,              NULL,            0, NULL, 0}
};
#define NMC_FIELDS_DEV_LIST_WIRED_PROP_ALL     "NAME,CARRIER"
#define NMC_FIELDS_DEV_LIST_WIRED_PROP_COMMON  "NAME,CARRIER"


/* Available fields for 'dev list' - wireless properties part */
static NmcOutputField nmc_fields_dev_list_wifi_prop[] = {
	{"NAME",       N_("NAME"),        18, NULL, 0},  /* 0 */
	{"WEP",        N_("WEP"),          5, NULL, 0},  /* 1 */
	{"WPA",        N_("WPA"),          5, NULL, 0},  /* 2 */
	{"WPA2",       N_("WPA2"),         6, NULL, 0},  /* 3 */
	{"TKIP",       N_("TKIP"),         6, NULL, 0},  /* 4 */
	{"CCMP",       N_("CCMP"),         6, NULL, 0},  /* 5 */
	{NULL,         NULL,               0, NULL, 0}
};
#define NMC_FIELDS_DEV_LIST_WIFI_PROP_ALL     "NAME,WEP,WPA,WPA2,TKIP,CCMP"
#define NMC_FIELDS_DEV_LIST_WIFI_PROP_COMMON  "NAME,WEP,WPA,WPA2,TKIP,CCMP"

#if WITH_WIMAX
/* Available fields for 'dev list' - wimax properties part */
static NmcOutputField nmc_fields_dev_list_wimax_prop[] = {
	{"NAME",       N_("NAME"),        18, NULL, 0},  /* 0 */
	{"CTR-FREQ",   N_("CTR-FREQ"),     7, NULL, 0},  /* 1 */
	{"RSSI",       N_("RSSI"),         5, NULL, 0},  /* 2 */
	{"CINR",       N_("CINR"),         5, NULL, 0},  /* 3 */
	{"TX-POW",     N_("TX-POW"),       5, NULL, 0},  /* 4 */
	{"BSID",       N_("BSID"),        18, NULL, 0},  /* 5 */
	{NULL,         NULL,               0, NULL, 0}
};
#define NMC_FIELDS_DEV_LIST_WIMAX_PROP_ALL     "NAME,CTR-FREQ,RSSI,CINR,TX-POW,BSID"
#define NMC_FIELDS_DEV_LIST_WIMAX_PROP_COMMON  "NAME,CTR-FREQ,RSSI,CINR,TX-POW,BSID"
#endif

/* Available fields for 'dev wifi list' */
static NmcOutputField nmc_fields_dev_wifi_list[] = {
	{"NAME",       N_("NAME"),        15, NULL, 0},  /* 0 */
	{"SSID",       N_("SSID"),        33, NULL, 0},  /* 1 */
	{"BSSID",      N_("BSSID"),       19, NULL, 0},  /* 2 */
	{"MODE",       N_("MODE"),        16, NULL, 0},  /* 3 */
	{"FREQ",       N_("FREQ"),        10, NULL, 0},  /* 4 */
	{"RATE",       N_("RATE"),        10, NULL, 0},  /* 5 */
	{"SIGNAL",     N_("SIGNAL"),       8, NULL, 0},  /* 6 */
	{"SECURITY",   N_("SECURITY"),    10, NULL, 0},  /* 7 */
	{"WPA-FLAGS",  N_("WPA-FLAGS"),   25, NULL, 0},  /* 8 */
	{"RSN-FLAGS",  N_("RSN-FLAGS"),   25, NULL, 0},  /* 9 */
	{"DEVICE",     N_("DEVICE"),      10, NULL, 0},  /* 10 */
	{"ACTIVE",     N_("ACTIVE"),       8, NULL, 0},  /* 11 */
	{"DBUS-PATH",  N_("DBUS-PATH"),   46, NULL, 0},  /* 12 */
	{NULL,         NULL,               0, NULL, 0}
};
#define NMC_FIELDS_DEV_WIFI_LIST_ALL           "SSID,BSSID,MODE,FREQ,RATE,SIGNAL,SECURITY,WPA-FLAGS,RSN-FLAGS,DEVICE,ACTIVE,DBUS-PATH"
#define NMC_FIELDS_DEV_WIFI_LIST_COMMON        "SSID,BSSID,MODE,FREQ,RATE,SIGNAL,SECURITY,ACTIVE"
#define NMC_FIELDS_DEV_WIFI_LIST_FOR_DEV_LIST  "NAME,"NMC_FIELDS_DEV_WIFI_LIST_COMMON

#if WITH_WIMAX
/* Available fields for 'dev wimax list' */
static NmcOutputField nmc_fields_dev_wimax_list[] = {
	{"NAME",       N_("NAME"),        15, NULL, 0},  /* 0 */
	{"NSP",        N_("NSP"),         33, NULL, 0},  /* 1 */
	{"SIGNAL",     N_("SIGNAL"),       8, NULL, 0},  /* 2 */
	{"TYPE",       N_("TYPE"),        16, NULL, 0},  /* 3 */
	{"DEVICE",     N_("DEVICE"),      10, NULL, 0},  /* 4 */
	{"ACTIVE",     N_("ACTIVE"),       8, NULL, 0},  /* 5 */
	{"DBUS-PATH",  N_("DBUS-PATH"),   46, NULL, 0},  /* 6 */
	{NULL,         NULL,               0, NULL, 0}
};
#define NMC_FIELDS_DEV_WIMAX_LIST_ALL           "NSP,SIGNAL,TYPE,DEVICE,ACTIVE,DBUS-PATH"
#define NMC_FIELDS_DEV_WIMAX_LIST_COMMON        "NSP,SIGNAL,TYPE,DEVICE,ACTIVE"
#define NMC_FIELDS_DEV_WIMAX_LIST_FOR_DEV_LIST  "NAME,"NMC_FIELDS_DEV_WIMAX_LIST_COMMON
#endif


/* glib main loop variable - defined in nmcli.c */
extern GMainLoop *loop;

static guint progress_id = 0;  /* ID of event source for displaying progress */

static void
usage (void)
{
	fprintf (stderr,
	         _("Usage: nmcli dev { COMMAND | help }\n\n"
#if WITH_WIMAX
	         "  COMMAND := { status | list | disconnect | wifi | wimax }\n\n"
#else
	         "  COMMAND := { status | list | disconnect | wifi }\n\n"
#endif
	         "  status\n"
	         "  list [iface <iface>]\n"
	         "  disconnect iface <iface> [--nowait] [--timeout <timeout>]\n"
	         "  wifi [list [iface <iface>] [bssid <BSSID>]]\n"
	         "  wifi connect <(B)SSID> [password <password>] [wep-key-type key|phrase] [iface <iface>] [bssid <BSSID>] [name <name>]\n"
	         "               [--private] [--nowait] [--timeout <timeout>]\n"
#if WITH_WIMAX
	         "  wimax [list [iface <iface>] [nsp <name>]]\n\n"
#endif
	         ));
}

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

static const char *
device_state_to_string (NMDeviceState state)
{
	switch (state) {
	case NM_DEVICE_STATE_UNMANAGED:
		return _("unmanaged");
	case NM_DEVICE_STATE_UNAVAILABLE:
		return _("unavailable");
	case NM_DEVICE_STATE_DISCONNECTED:
		return _("disconnected");
	case NM_DEVICE_STATE_PREPARE:
		return _("connecting (prepare)");
	case NM_DEVICE_STATE_CONFIG:
		return _("connecting (configuring)");
	case NM_DEVICE_STATE_NEED_AUTH:
		return _("connecting (need authentication)");
	case NM_DEVICE_STATE_IP_CONFIG:
		return _("connecting (getting IP configuration)");
	case NM_DEVICE_STATE_IP_CHECK:
		return _("connecting (checking IP connectivity)");
	case NM_DEVICE_STATE_SECONDARIES:
		return _("connecting (starting secondary connections)");
	case NM_DEVICE_STATE_ACTIVATED:
		return _("connected");
	case NM_DEVICE_STATE_DEACTIVATING:
		return _("deactivating");
	case NM_DEVICE_STATE_FAILED:
		return _("connection failed");
	default:
		return _("unknown");
	}
}

static const char *
device_reason_to_string (NMDeviceStateReason reason)
{
	switch (reason) {
	case NM_DEVICE_STATE_REASON_NONE:
		return _("No reason given");

	case NM_DEVICE_STATE_REASON_UNKNOWN:
		return _("Unknown error");

	case NM_DEVICE_STATE_REASON_NOW_MANAGED:
		return _("Device is now managed");

	case NM_DEVICE_STATE_REASON_NOW_UNMANAGED:
		return _("Device is now unmanaged");

	case NM_DEVICE_STATE_REASON_CONFIG_FAILED:
		return _("The device could not be readied for configuration");

	case NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE:
		return _("IP configuration could not be reserved (no available address, timeout, etc)");

	case NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED:
		return _("The IP configuration is no longer valid");

	case NM_DEVICE_STATE_REASON_NO_SECRETS:
		return _("Secrets were required, but not provided");

	case NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT:
		return _("802.1X supplicant disconnected");

	case NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED:
		return _("802.1X supplicant configuration failed");

	case NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED:
		return _("802.1X supplicant failed");

	case NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT:
		return _("802.1X supplicant took too long to authenticate");

	case NM_DEVICE_STATE_REASON_PPP_START_FAILED:
		return _("PPP service failed to start");

	case NM_DEVICE_STATE_REASON_PPP_DISCONNECT:
		return _("PPP service disconnected");

	case NM_DEVICE_STATE_REASON_PPP_FAILED:
		return _("PPP failed");

	case NM_DEVICE_STATE_REASON_DHCP_START_FAILED:
		return _("DHCP client failed to start");

	case NM_DEVICE_STATE_REASON_DHCP_ERROR:
		return _("DHCP client error");

	case NM_DEVICE_STATE_REASON_DHCP_FAILED:
		return _("DHCP client failed");

	case NM_DEVICE_STATE_REASON_SHARED_START_FAILED:
		return _("Shared connection service failed to start");

	case NM_DEVICE_STATE_REASON_SHARED_FAILED:
		return _("Shared connection service failed");

	case NM_DEVICE_STATE_REASON_AUTOIP_START_FAILED:
		return _("AutoIP service failed to start");

	case NM_DEVICE_STATE_REASON_AUTOIP_ERROR:
		return _("AutoIP service error");

	case NM_DEVICE_STATE_REASON_AUTOIP_FAILED:
		return _("AutoIP service failed");

	case NM_DEVICE_STATE_REASON_MODEM_BUSY:
		return _("The line is busy");

	case NM_DEVICE_STATE_REASON_MODEM_NO_DIAL_TONE:
		return _("No dial tone");

	case NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER:
		return _("No carrier could be established");

	case NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT:
		return _("The dialing request timed out");

	case NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED:
		return _("The dialing attempt failed");

	case NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED:
		return _("Modem initialization failed");

	case NM_DEVICE_STATE_REASON_GSM_APN_FAILED:
		return _("Failed to select the specified APN");

	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING:
		return _("Not searching for networks");

	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED:
		return _("Network registration denied");

	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT:
		return _("Network registration timed out");

	case NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED:
		return _("Failed to register with the requested network");

	case NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED:
		return _("PIN check failed");

	case NM_DEVICE_STATE_REASON_FIRMWARE_MISSING:
		return _("Necessary firmware for the device may be missing");

	case NM_DEVICE_STATE_REASON_REMOVED:
		return _("The device was removed");

	case NM_DEVICE_STATE_REASON_SLEEPING:
		return _("NetworkManager went to sleep");

	case NM_DEVICE_STATE_REASON_CONNECTION_REMOVED:
		return _("The device's active connection disappeared");

	case NM_DEVICE_STATE_REASON_USER_REQUESTED:
		return _("Device disconnected by user or client");

	case NM_DEVICE_STATE_REASON_CARRIER:
		return _("Carrier/link changed");

	case NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED:
		return _("The device's existing connection was assumed");

	case NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE:
		return _("The supplicant is now available");

	case NM_DEVICE_STATE_REASON_MODEM_NOT_FOUND:
		return _("The modem could not be found");

	case NM_DEVICE_STATE_REASON_BT_FAILED:
		return _("The Bluetooth connection failed or timed out");

	case NM_DEVICE_STATE_REASON_GSM_SIM_NOT_INSERTED:
		return _("GSM Modem's SIM card not inserted");

	case NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED:
		return _("GSM Modem's SIM PIN required");

	case NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED:
		return _("GSM Modem's SIM PUK required");

	case NM_DEVICE_STATE_REASON_GSM_SIM_WRONG:
		return _("GSM Modem's SIM wrong");

	case NM_DEVICE_STATE_REASON_INFINIBAND_MODE:
		return _("InfiniBand device does not support connected mode");

        case NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED:
		return _("A dependency of the connection failed");
	default:
		return _("Unknown");
	}
}

/* Convert device type to string. Use setting names strings to match with
 * connection type names.
 */
static const char *
device_type_to_string (NMDevice *device)
{
	NMDeviceModemCapabilities caps = NM_DEVICE_MODEM_CAPABILITY_NONE;

	switch (nm_device_get_device_type (device)) {
	case NM_DEVICE_TYPE_ETHERNET:
		return NM_SETTING_WIRED_SETTING_NAME;
	case NM_DEVICE_TYPE_WIFI:
		return NM_SETTING_WIRELESS_SETTING_NAME;
	case NM_DEVICE_TYPE_MODEM:
		caps = nm_device_modem_get_current_capabilities (NM_DEVICE_MODEM (device));
		if (caps & NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS)
			return NM_SETTING_GSM_SETTING_NAME;
		else if (caps & NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO)
			return NM_SETTING_CDMA_SETTING_NAME;
		return _("Unknown");
	case NM_DEVICE_TYPE_BT:
		return NM_SETTING_BLUETOOTH_SETTING_NAME;
	case NM_DEVICE_TYPE_OLPC_MESH:
		return NM_SETTING_OLPC_MESH_SETTING_NAME;
#if WITH_WIMAX
	case NM_DEVICE_TYPE_WIMAX:
		return NM_SETTING_WIMAX_SETTING_NAME;
#endif
	case NM_DEVICE_TYPE_INFINIBAND:
		return NM_SETTING_INFINIBAND_SETTING_NAME;
	case NM_DEVICE_TYPE_BOND:
		return NM_SETTING_BOND_SETTING_NAME;
	case NM_DEVICE_TYPE_VLAN:
		return NM_SETTING_VLAN_SETTING_NAME;
	default:
		return _("Unknown");
	}
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
	const char* active_bssid;
	const char* device;
} APInfo;

static void
detail_access_point (gpointer data, gpointer user_data)
{
	NMAccessPoint *ap = NM_ACCESS_POINT (data);
	APInfo *info = (APInfo *) user_data;
	gboolean active = FALSE;
	NM80211ApFlags flags;
	NM80211ApSecurityFlags wpa_flags, rsn_flags;
	guint32 freq, bitrate;
	guint8 strength;
	const GByteArray *ssid;
	const char *bssid;
	NM80211Mode mode;
	char *freq_str, *ssid_str, *bitrate_str, *strength_str, *wpa_flags_str, *rsn_flags_str;
	GString *security_str;
	char *ap_name;

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
	strength = nm_access_point_get_strength (ap);

	/* Convert to strings */
	ssid_str = ssid_to_printable ((const char *) ssid->data, ssid->len);
	freq_str = g_strdup_printf (_("%u MHz"), freq);
	bitrate_str = g_strdup_printf (_("%u MB/s"), bitrate/1000);
	strength_str = g_strdup_printf ("%u", strength);
	wpa_flags_str = ap_wpa_rsn_flags_to_string (wpa_flags);
	rsn_flags_str = ap_wpa_rsn_flags_to_string (rsn_flags);

	security_str = g_string_new (NULL);
	if (   !(flags & NM_802_11_AP_FLAGS_PRIVACY)
	    &&  (wpa_flags != NM_802_11_AP_SEC_NONE)
	    &&  (rsn_flags != NM_802_11_AP_SEC_NONE))
		g_string_append (security_str, _("Encrypted: "));

	if (   (flags & NM_802_11_AP_FLAGS_PRIVACY)
	    && (wpa_flags == NM_802_11_AP_SEC_NONE)
	    && (rsn_flags == NM_802_11_AP_SEC_NONE))
		g_string_append (security_str, _("WEP "));
	if (wpa_flags != NM_802_11_AP_SEC_NONE)
		g_string_append (security_str, _("WPA "));
	if (rsn_flags != NM_802_11_AP_SEC_NONE)
		g_string_append (security_str, _("WPA2 "));
	if (   (wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
	    || (rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
		g_string_append (security_str, _("Enterprise "));

	if (security_str->len > 0)
		g_string_truncate (security_str, security_str->len-1);  /* Chop off last space */

	ap_name = g_strdup_printf ("AP%d", info->index++); /* AP */
	info->nmc->allowed_fields[0].value = ap_name;
	info->nmc->allowed_fields[1].value = ssid_str;
	info->nmc->allowed_fields[2].value = bssid;
	info->nmc->allowed_fields[3].value = mode == NM_802_11_MODE_ADHOC ? _("Ad-Hoc") : mode == NM_802_11_MODE_INFRA ? _("Infrastructure") : _("Unknown");
	info->nmc->allowed_fields[4].value = freq_str;
	info->nmc->allowed_fields[5].value = bitrate_str;
	info->nmc->allowed_fields[6].value = strength_str;
	info->nmc->allowed_fields[7].value = security_str->str;
	info->nmc->allowed_fields[8].value = wpa_flags_str;
	info->nmc->allowed_fields[9].value = rsn_flags_str;
	info->nmc->allowed_fields[10].value = info->device;
	info->nmc->allowed_fields[11].value = active ? _("yes") : _("no");
	info->nmc->allowed_fields[12].value = nm_object_get_path (NM_OBJECT (ap));

	info->nmc->print_fields.flags &= ~NMC_PF_FLAG_MAIN_HEADER_ADD & ~NMC_PF_FLAG_MAIN_HEADER_ONLY & ~NMC_PF_FLAG_FIELD_NAMES; /* Clear header flags */
	print_fields (info->nmc->print_fields, info->nmc->allowed_fields);

	g_free (ap_name);
	g_free (ssid_str);
	g_free (freq_str);
	g_free (bitrate_str);
	g_free (strength_str);
	g_free (wpa_flags_str);
	g_free (rsn_flags_str);
	g_string_free (security_str, TRUE);
}

#if WITH_WIMAX
static void
detail_wimax_nsp (NMWimaxNsp *nsp, NmCli *nmc, NMDevice *dev, int idx)
{
	NMDeviceWimax *wimax = NM_DEVICE_WIMAX (dev);
	char *nsp_name, *quality_str;
	const char *ntype;
	gboolean active = FALSE;

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
	nsp_name = g_strdup_printf ("NSP%d", idx); /* NSP */

	nmc->allowed_fields[0].value = nsp_name;
	nmc->allowed_fields[1].value = nm_wimax_nsp_get_name (nsp);
	nmc->allowed_fields[2].value = quality_str;
	nmc->allowed_fields[3].value = ntype;
	nmc->allowed_fields[4].value = nm_device_get_iface (dev);
	nmc->allowed_fields[5].value = active ? _("yes") : _("no");
	nmc->allowed_fields[6].value = nm_object_get_path (NM_OBJECT (nsp));

	nmc->print_fields.flags &= ~NMC_PF_FLAG_MAIN_HEADER_ADD & ~NMC_PF_FLAG_MAIN_HEADER_ONLY & ~NMC_PF_FLAG_FIELD_NAMES; /* Clear header flags */
	print_fields (nmc->print_fields, nmc->allowed_fields);

	g_free (nsp_name);
	g_free (quality_str);
}
#endif

struct cb_info {
	NMClient *client;
	const GPtrArray *active;
};

static void
show_device_info (gpointer data, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (data);
	NmCli *nmc = (NmCli *) user_data;
	GError *error = NULL;
	APInfo *info;
	const char *hwaddr = NULL;
	NMDeviceState state = NM_DEVICE_STATE_UNKNOWN;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	NMDeviceCapabilities caps;
	NMActiveConnection *acon;
	guint32 speed;
	char *speed_str = NULL;
	char *state_str = NULL;
	char *reason_str = NULL;
	GArray *sections_array;
	int k;
	char *fields_str;
	char *fields_all =    NMC_FIELDS_DEV_LIST_SECTIONS_ALL;
	char *fields_common = NMC_FIELDS_DEV_LIST_SECTIONS_COMMON;
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

	sections_array = parse_output_fields (fields_str, nmc_fields_dev_list_sections, &error);
	if (error) {
		if (error->code == 0)
			g_string_printf (nmc->return_text, _("Error: 'dev list': %s"), error->message);
		else
			g_string_printf (nmc->return_text, _("Error: 'dev list': %s; allowed fields: %s"), error->message, NMC_FIELDS_DEV_LIST_SECTIONS_ALL);
		g_error_free (error);
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		return;
	}

	/* Main header */
	nmc->allowed_fields = nmc_fields_dev_list_general;
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ONLY;
	nmc->print_fields.header_name = _("Device details");
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_DEV_LIST_GENERAL_ALL, nmc->allowed_fields, NULL);
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

	/* Loop through the required sections and print them. */
	for (k = 0; k < sections_array->len; k++) {
		int section_idx = g_array_index (sections_array, int, k);

		if (nmc->print_output != NMC_PRINT_TERSE && !nmc->multiline_output && was_output)
			printf ("\n"); /* Empty line */

		was_output = FALSE;

		state = nm_device_get_state_reason (device, &reason);

		/* section GENERAL */
		if (!strcasecmp (nmc_fields_dev_list_sections[section_idx].name, nmc_fields_dev_list_sections[0].name)) {
			nmc->allowed_fields = nmc_fields_dev_list_general;
			nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
			nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_DEV_LIST_GENERAL_ALL, nmc->allowed_fields, NULL);
			print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

			if (NM_IS_DEVICE_ETHERNET (device))
				hwaddr = nm_device_ethernet_get_hw_address (NM_DEVICE_ETHERNET (device));
			else if (NM_IS_DEVICE_WIFI (device))
				hwaddr = nm_device_wifi_get_hw_address (NM_DEVICE_WIFI (device));
#if WITH_WIMAX
			else if (NM_IS_DEVICE_WIMAX (device))
				hwaddr = nm_device_wimax_get_hw_address (NM_DEVICE_WIMAX (device));
#endif
			else if (NM_IS_DEVICE_INFINIBAND (device))
				hwaddr = nm_device_infiniband_get_hw_address (NM_DEVICE_INFINIBAND (device));
			else if (NM_IS_DEVICE_BOND (device))
				hwaddr = nm_device_bond_get_hw_address (NM_DEVICE_BOND (device));
			else if (NM_IS_DEVICE_VLAN (device))
				hwaddr = nm_device_vlan_get_hw_address (NM_DEVICE_VLAN (device));

			state_str = g_strdup_printf ("%d (%s)", state, device_state_to_string (state));
			reason_str = g_strdup_printf ("%d (%s)", reason, device_reason_to_string (reason));

			nmc->allowed_fields[0].value = nmc_fields_dev_list_sections[0].name;  /* "GENERAL"*/
			nmc->allowed_fields[1].value = nm_device_get_iface (device);
			nmc->allowed_fields[2].value = device_type_to_string (device);
			nmc->allowed_fields[3].value = nm_device_get_vendor (device);
			nmc->allowed_fields[4].value = nm_device_get_product (device);
			nmc->allowed_fields[5].value = nm_device_get_driver (device) ? nm_device_get_driver (device) : _("(unknown)");
			nmc->allowed_fields[6].value = hwaddr ? hwaddr : _("(unknown)");
			nmc->allowed_fields[7].value = state_str;
			nmc->allowed_fields[8].value = reason_str;
			nmc->allowed_fields[9].value = nm_device_get_udi (device);
			nmc->allowed_fields[10].value = nm_device_get_ip_iface (device);
			nmc->allowed_fields[11].value = nm_device_get_managed (device) ? _("yes") : _("no");
			nmc->allowed_fields[12].value = nm_device_get_firmware_missing (device) ? _("yes") : _("no");
			nmc->allowed_fields[13].value = (acon = nm_device_get_active_connection (device)) ?
			                                   nm_object_get_path (NM_OBJECT (acon)) : _("not connected");

			nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
			print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */
			g_free (state_str);
			g_free (reason_str);
			was_output = TRUE;
		}

		/* section CAPABILITIES */
		if (!strcasecmp (nmc_fields_dev_list_sections[section_idx].name, nmc_fields_dev_list_sections[1].name)) {
			nmc->allowed_fields = nmc_fields_dev_list_cap;
			nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
			nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_DEV_LIST_CAP_ALL, nmc->allowed_fields, NULL);
			print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

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
			if (speed)
				speed_str = g_strdup_printf (_("%u Mb/s"), speed);

			nmc->allowed_fields[0].value = nmc_fields_dev_list_sections[1].name;  /* "CAPABILITIES" */
			nmc->allowed_fields[1].value = (caps & NM_DEVICE_CAP_CARRIER_DETECT) ? _("yes") : _("no");
			nmc->allowed_fields[2].value = speed_str ? speed_str : _("unknown");

			nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
			print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */
			g_free (speed_str);
			was_output = TRUE;
		}

		/* Wireless specific information */
		if ((NM_IS_DEVICE_WIFI (device))) {
			NMDeviceWifiCapabilities wcaps;
			NMAccessPoint *active_ap = NULL;
			const char *active_bssid = NULL;
			const GPtrArray *aps;

			/* section WIFI-PROPERTIES */
			if (!strcasecmp (nmc_fields_dev_list_sections[section_idx].name, nmc_fields_dev_list_sections[2].name)) {
				wcaps = nm_device_wifi_get_capabilities (NM_DEVICE_WIFI (device));

				nmc->allowed_fields = nmc_fields_dev_list_wifi_prop;
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
				nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_DEV_LIST_WIFI_PROP_ALL, nmc->allowed_fields, NULL);
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

				nmc->allowed_fields[0].value = nmc_fields_dev_list_sections[2].name;  /* "WIFI-PROPERTIES" */
				nmc->allowed_fields[1].value = (wcaps & (NM_WIFI_DEVICE_CAP_CIPHER_WEP40 | NM_WIFI_DEVICE_CAP_CIPHER_WEP104)) ? _("yes") : _("no");
				nmc->allowed_fields[2].value = (wcaps & NM_WIFI_DEVICE_CAP_WPA) ? _("yes") : _("no");
				nmc->allowed_fields[3].value = (wcaps & NM_WIFI_DEVICE_CAP_RSN) ? _("yes") : _("no");
				nmc->allowed_fields[4].value = (wcaps & NM_WIFI_DEVICE_CAP_CIPHER_TKIP) ? _("yes") : _("no");
				nmc->allowed_fields[5].value = (wcaps & NM_WIFI_DEVICE_CAP_CIPHER_CCMP) ? _("yes") : _("no");

				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */
				was_output = TRUE;
			}

			/* section AP */
			if (!strcasecmp (nmc_fields_dev_list_sections[section_idx].name, nmc_fields_dev_list_sections[3].name)) {
				if (state == NM_DEVICE_STATE_ACTIVATED) {
					active_ap = nm_device_wifi_get_active_access_point (NM_DEVICE_WIFI (device));
					active_bssid = active_ap ? nm_access_point_get_bssid (active_ap) : NULL;
				}

				nmc->allowed_fields = nmc_fields_dev_wifi_list;
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
				nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_DEV_WIFI_LIST_FOR_DEV_LIST, nmc->allowed_fields, NULL);
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
				info = g_malloc0 (sizeof (APInfo));
				info->nmc = nmc;
				info->index = 1;
				info->active_bssid = active_bssid;
				info->device = nm_device_get_iface (device);
				aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (device));
				if (aps && aps->len)
					g_ptr_array_foreach ((GPtrArray *) aps, detail_access_point, (gpointer) info);
				g_free (info);
				was_output = TRUE;
			}
		} else if (NM_IS_DEVICE_ETHERNET (device)) {
			/* WIRED-PROPERTIES */
			if (!strcasecmp (nmc_fields_dev_list_sections[section_idx].name, nmc_fields_dev_list_sections[4].name)) {
				nmc->allowed_fields = nmc_fields_dev_list_wired_prop;
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
				nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_DEV_LIST_WIRED_PROP_ALL, nmc->allowed_fields, NULL);
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

				nmc->allowed_fields[0].value = nmc_fields_dev_list_sections[4].name;  /* "WIRED-PROPERTIES" */
				nmc->allowed_fields[1].value = (nm_device_ethernet_get_carrier (NM_DEVICE_ETHERNET (device))) ? _("on") : _("off");

				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */
				was_output = TRUE;
			}
		}
#if WITH_WIMAX
		else if (NM_IS_DEVICE_WIMAX (device)) {
			/* WIMAX-PROPERTIES */
			if (!strcasecmp (nmc_fields_dev_list_sections[section_idx].name, nmc_fields_dev_list_sections[5].name)) {
				char *cfreq = NULL, *rssi = NULL, *cinr = NULL, *txpow = NULL;
				guint tmp_uint;
				gint tmp_int;
				const char *bsid;

				nmc->allowed_fields = nmc_fields_dev_list_wimax_prop;
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
				nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_DEV_LIST_WIMAX_PROP_ALL, nmc->allowed_fields, NULL);
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

				nmc->allowed_fields[0].value = nmc_fields_dev_list_sections[5].name;  /* "WIMAX-PROPERTIES" */

				/* Center frequency */
				tmp_uint = nm_device_wimax_get_center_frequency (NM_DEVICE_WIMAX (device));
				if (tmp_uint)
					cfreq = g_strdup_printf ("%'.1f MHz", (double) tmp_uint / 1000.0);
				nmc->allowed_fields[1].value = cfreq ? cfreq : "";

				/* RSSI */
				tmp_int = nm_device_wimax_get_rssi (NM_DEVICE_WIMAX (device));
				if (tmp_int)
					rssi = g_strdup_printf ("%d dBm", tmp_int);
				nmc->allowed_fields[2].value = rssi ? rssi : "";

				/* CINR */
				tmp_int = nm_device_wimax_get_cinr (NM_DEVICE_WIMAX (device));
				if (tmp_int)
					cinr = g_strdup_printf ("%d dB", tmp_int);
				nmc->allowed_fields[3].value = cinr ? cinr : "";

				/* TX Power */
				tmp_int = nm_device_wimax_get_tx_power (NM_DEVICE_WIMAX (device));
				if (tmp_int)
					txpow = g_strdup_printf ("%'.2f dBm", (float) tmp_int / 2.0);
				nmc->allowed_fields[4].value = txpow ? txpow : "";

				/* BSID */
				bsid = nm_device_wimax_get_bsid (NM_DEVICE_WIMAX (device));
				nmc->allowed_fields[5].value = bsid ? bsid : "";

				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */
				was_output = TRUE;
			}

			/* section NSP */
			if (!strcasecmp (nmc_fields_dev_list_sections[section_idx].name, nmc_fields_dev_list_sections[6].name)) {
				const GPtrArray *nsps;
				int g, idx = 1;

				nmc->allowed_fields = nmc_fields_dev_wimax_list;
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
				nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_DEV_WIMAX_LIST_FOR_DEV_LIST, nmc->allowed_fields, NULL);
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;

				nsps = nm_device_wimax_get_nsps (NM_DEVICE_WIMAX (device));
				for (g = 0; nsps && g < nsps->len; g++) {
					NMWimaxNsp *nsp = g_ptr_array_index (nsps, g);

					detail_wimax_nsp (nsp, nmc, device, idx++);
				}
				was_output = TRUE;
			}
		}
#endif

		/* IP configuration info */
		if (state == NM_DEVICE_STATE_ACTIVATED) {
			NMIP4Config *cfg4 = nm_device_get_ip4_config (device);
			NMIP6Config *cfg6 = nm_device_get_ip6_config (device);
			NMDHCP4Config *dhcp4 = nm_device_get_dhcp4_config (device);
			NMDHCP6Config *dhcp6 = nm_device_get_dhcp6_config (device);

			/* IP4 */
			if (cfg4 && !strcasecmp (nmc_fields_dev_list_sections[section_idx].name, nmc_fields_dev_list_sections[7].name))
				was_output = print_ip4_config (cfg4, nmc, nmc_fields_dev_list_sections[7].name);

			/* DHCP4 */
			if (dhcp4 && !strcasecmp (nmc_fields_dev_list_sections[section_idx].name, nmc_fields_dev_list_sections[8].name))
				was_output = print_dhcp4_config (dhcp4, nmc, nmc_fields_dev_list_sections[8].name);

			/* IP6 */
			if (cfg6 && !strcasecmp (nmc_fields_dev_list_sections[section_idx].name, nmc_fields_dev_list_sections[9].name))
				was_output = print_ip6_config (cfg6, nmc, nmc_fields_dev_list_sections[9].name);

			/* DHCP6 */
			if (dhcp6 && !strcasecmp (nmc_fields_dev_list_sections[section_idx].name, nmc_fields_dev_list_sections[10].name))
				was_output = print_dhcp6_config (dhcp6, nmc, nmc_fields_dev_list_sections[10].name);
		}
	}

	if (sections_array)
		g_array_free (sections_array, TRUE);
}

static void
show_device_status (NMDevice *device, NmCli *nmc)
{
	nmc->allowed_fields[0].value = nm_device_get_iface (device);
	nmc->allowed_fields[1].value = device_type_to_string (device);
	nmc->allowed_fields[2].value = device_state_to_string (nm_device_get_state (device));
	nmc->allowed_fields[3].value = nm_object_get_path (NM_OBJECT (device));

	nmc->print_fields.flags &= ~NMC_PF_FLAG_MAIN_HEADER_ADD & ~NMC_PF_FLAG_MAIN_HEADER_ONLY & ~NMC_PF_FLAG_FIELD_NAMES; /* Clear header flags */
	print_fields (nmc->print_fields, nmc->allowed_fields);
}

static NMCResultCode
do_devices_status (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;
	const GPtrArray *devices;
	int i;
	char *fields_str;
	char *fields_all =    NMC_FIELDS_DEV_STATUS_ALL;
	char *fields_common = NMC_FIELDS_DEV_STATUS_COMMON;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

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

	nmc->allowed_fields = nmc_fields_dev_status;
	nmc->print_fields.indices = parse_output_fields (fields_str, nmc->allowed_fields, &error);

	if (error) {
		if (error->code == 0)
			g_string_printf (nmc->return_text, _("Error: 'dev status': %s"), error->message);
		else
			g_string_printf (nmc->return_text, _("Error: 'dev status': %s; allowed fields: %s"), error->message, NMC_FIELDS_DEV_STATUS_ALL);
		g_error_free (error);
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

	if (!nmc_versions_match (nmc))
		goto error;

	/* Print headers */
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ADD | NMC_PF_FLAG_FIELD_NAMES;
	nmc->print_fields.header_name = _("Status of devices");
	print_fields (nmc->print_fields, nmc->allowed_fields);

	nmc->get_client (nmc);
	devices = nm_client_get_devices (nmc->client);
	for (i = 0; devices && (i < devices->len); i++) {
		NMDevice *device = g_ptr_array_index (devices, i);
		show_device_status (device, nmc);
	}

	return NMC_RESULT_SUCCESS;

error:
	return nmc->return_value;
}

static NMCResultCode
do_devices_list (NmCli *nmc, int argc, char **argv)
{
	const GPtrArray *devices;
	GError *error = NULL;
	NMDevice *device = NULL;
	const char *iface = NULL;
	gboolean iface_specified = FALSE;
	int i;

	while (argc > 0) {
		if (strcmp (*argv, "iface") == 0) {
			iface_specified = TRUE;

			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: '%s' argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}

			iface = *argv;
		} else {
			fprintf (stderr, _("Unknown parameter: %s\n"), *argv);
		}

		argc--;
		argv++;
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

	if (!nmc_versions_match (nmc))
		goto error;

	nmc->get_client (nmc);
	devices = nm_client_get_devices (nmc->client);

	if (iface_specified) {
		for (i = 0; devices && (i < devices->len); i++) {
			NMDevice *candidate = g_ptr_array_index (devices, i);
			const char *dev_iface = nm_device_get_iface (candidate);

			if (!strcmp (dev_iface, iface))
				device = candidate;
		}
		if (!device) {
			g_string_printf (nmc->return_text, _("Error: Device '%s' not found."), iface);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			goto error;
		}
		show_device_info (device, nmc);
	} else {
		if (devices)
			g_ptr_array_foreach ((GPtrArray *) devices, show_device_info, nmc);
	}

error:
	return nmc->return_value;
}

static void
device_state_cb (NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;
	NMDeviceState state;

	state = nm_device_get_state (device);

	if (state == NM_DEVICE_STATE_DISCONNECTED) {
		g_string_printf (nmc->return_text, _("Success: Device '%s' successfully disconnected."), nm_device_get_iface (device));
		quit ();
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
		printf (_("Device state: %d (%s)\n"), state, device_state_to_string (state));

		if (nmc->nowait_flag || state == NM_DEVICE_STATE_DISCONNECTED) {
			/* Don't want to wait or device already disconnected */
			quit ();
		} else {
			g_signal_connect (device, "notify::state", G_CALLBACK (device_state_cb), nmc);
			/* Start timer not to loop forever if "notify::state" signal is not issued */
			g_timeout_add_seconds (nmc->timeout, timeout_cb, nmc);
		}

	}
}

static NMCResultCode
do_device_disconnect (NmCli *nmc, int argc, char **argv)
{
	const GPtrArray *devices;
	GError *error = NULL;
	NMDevice *device = NULL;
	const char *iface = NULL;
	gboolean iface_specified = FALSE;
	gboolean wait = TRUE;
	int i;

	/* Set default timeout for disconnect operation */
	nmc->timeout = 10;

	while (argc > 0) {
		if (strcmp (*argv, "iface") == 0) {
			iface_specified = TRUE;

			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}

			iface = *argv;
		} else if (strcmp (*argv, "--nowait") == 0) {
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

	if (!iface_specified) {
		g_string_printf (nmc->return_text, _("Error: iface has to be specified."));
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

	if (!nmc_versions_match (nmc))
		goto error;

	nmc->get_client (nmc);
	devices = nm_client_get_devices (nmc->client);
	for (i = 0; devices && (i < devices->len); i++) {
		NMDevice *candidate = g_ptr_array_index (devices, i);
		const char *dev_iface = nm_device_get_iface (candidate);

		if (!strcmp (dev_iface, iface))
			device = candidate;
	}

	if (!device) {
		g_string_printf (nmc->return_text, _("Error: Device '%s' not found."), iface);
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto error;
	}

	/* Use nowait_flag instead of should_wait because exitting has to be postponed till disconnect_device_cb()
	 * is called, giving NM time to check our permissions */
	nmc->nowait_flag = !wait;
	nmc->should_wait = TRUE;
	nm_device_disconnect (device, disconnect_device_cb, nmc);

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

	if (nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED) {
		active_ap = nm_device_wifi_get_active_access_point (NM_DEVICE_WIFI (device));
		active_bssid = active_ap ? nm_access_point_get_bssid (active_ap) : NULL;
	}

	info = g_malloc0 (sizeof (APInfo));
	info->nmc = nmc;
	info->index = 1;
	info->active_bssid = active_bssid;
	info->device = nm_device_get_iface (device);
	aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (device));
	if (aps && aps->len)
		g_ptr_array_foreach ((GPtrArray *) aps, detail_access_point, (gpointer) info);
	g_free (info);
}

static NMCResultCode
do_device_wifi_list (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;
	NMDevice *device = NULL;
	NMAccessPoint *ap = NULL;
	const char *iface = NULL;
	const char *bssid_user = NULL;
	const GPtrArray *devices;
	const GPtrArray *aps;
	APInfo *info;
	int i, j;
	char *fields_str;
	char *fields_all =    NMC_FIELDS_DEV_WIFI_LIST_ALL;
	char *fields_common = NMC_FIELDS_DEV_WIFI_LIST_COMMON;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	while (argc > 0) {
		if (strcmp (*argv, "iface") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			iface = *argv;
		} else if (strcmp (*argv, "bssid") == 0 || strcmp (*argv, "hwaddr") == 0) {
			/* hwaddr is deprecated and will be removed later */
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
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

	nmc->allowed_fields = nmc_fields_dev_wifi_list;
	nmc->print_fields.indices = parse_output_fields (fields_str, nmc->allowed_fields, &error);

	if (error) {
		if (error->code == 0)
			g_string_printf (nmc->return_text, _("Error: 'dev wifi': %s"), error->message);
		else
			g_string_printf (nmc->return_text, _("Error: 'dev wifi': %s; allowed fields: %s"), error->message, NMC_FIELDS_DEV_WIFI_LIST_ALL);
		g_error_free (error);
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

	if (!nmc_versions_match (nmc))
		goto error;

	/* Print headers */
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ADD | NMC_PF_FLAG_FIELD_NAMES;
	nmc->print_fields.header_name = _("WiFi scan list");

	nmc->get_client (nmc);
	devices = nm_client_get_devices (nmc->client);
	if (iface) {
		/* Device specified - list only APs of this interface */
		for (i = 0; devices && (i < devices->len); i++) {
			NMDevice *candidate = g_ptr_array_index (devices, i);
			const char *dev_iface = nm_device_get_iface (candidate);

			if (!strcmp (dev_iface, iface)) {
				device = candidate;
				break;
			}
		}

		if (!device) {
			g_string_printf (nmc->return_text, _("Error: Device '%s' not found."), iface);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			goto error;
		}

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
					g_string_printf (nmc->return_text, _("Error: Access point with bssid '%s' not found."), bssid_user);
					nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
					goto error;
				}
				info = g_malloc0 (sizeof (APInfo));
				info->nmc = nmc;
				info->index = 1;
				info->active_bssid = NULL;
				info->device = nm_device_get_iface (device);
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */
				detail_access_point (ap, info);
				g_free (info);
			} else {
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */
				show_acces_point_info (device, nmc);
			}
		} else {
			g_string_printf (nmc->return_text, _("Error: Device '%s' is not a WiFi device."), iface);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			goto error;
		}
	} else {
		/* List APs for all devices */
		print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */
		if (bssid_user) {
			/* Specific AP requested - list only that */
			for (i = 0; devices && (i < devices->len); i++) {
				NMDevice *dev = g_ptr_array_index (devices, i);

				if (!NM_IS_DEVICE_WIFI (dev))
					continue;

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
						info->active_bssid = NULL;
						info->device = nm_device_get_iface (dev);
						detail_access_point (ap, info);
						g_free (info);
					}
					g_free (bssid_up);
				}
			}
			if (!ap) {
				g_string_printf (nmc->return_text, _("Error: Access point with bssid '%s' not found."), bssid_user);
				nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
				goto error;
			}
		} else {
			for (i = 0; devices && (i < devices->len); i++) {
				NMDevice *dev = g_ptr_array_index (devices, i);
				if (NM_IS_DEVICE_WIFI (dev))
					show_acces_point_info (dev, nmc);
			}
		}
	}

error:
	return nmc->return_value;
}

static gboolean
progress_cb (gpointer user_data)
{
	NMDevice *device = (NMDevice *) user_data;

	nmc_terminal_show_progress (device ? device_state_to_string (nm_device_get_state (device)) : "");

	return TRUE;
}

static void
monitor_device_state_cb (NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
	NmCli *nmc = (NmCli *) user_data;
	NMDeviceState state;
	NMDeviceStateReason reason;

	state = nm_device_get_state_reason (device, &reason);

	if (state == NM_DEVICE_STATE_ACTIVATED) {
		if (nmc->print_output == NMC_PRINT_PRETTY) {
			NMActiveConnection *active = nm_device_get_active_connection (device);

			nmc_terminal_erase_line ();
			printf (_("Connection with UUID '%s' created and activated on device '%s'\n"),
			        nm_active_connection_get_uuid (active), nm_device_get_iface (device));
		}
		quit ();
	} else if (state == NM_DEVICE_STATE_FAILED) {
		g_string_printf (nmc->return_text, _("Error: Connection activation failed: (%d) %s."),
		                 reason, device_reason_to_string (reason));
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
			if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED && nmc->print_output == NMC_PRINT_PRETTY) {
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
			if (strcmp (dev_iface, iface) == 0) {
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
			const GByteArray *candidate_ssid = nm_access_point_get_ssid (candidate_ap);
			char *ssid_tmp = nm_utils_ssid_to_utf8 (candidate_ssid);

			/* Compare SSIDs */
			if (strcmp (ssid, ssid_tmp) == 0) {
				ap = candidate_ap;
				g_free (ssid_tmp);
				break;
			}
			g_free (ssid_tmp);
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
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	AddAndActivateInfo *info;
	const char *param_user = NULL;
	const char *iface = NULL;
	const char *bssid = NULL;
	const char *password = NULL;
	const char *con_name = NULL;
	gboolean private = FALSE;
	gboolean wait = TRUE;
	gboolean wep_passphrase = FALSE;
	GByteArray *bssid1_arr = NULL;
	GByteArray *bssid2_arr = NULL;
	const GPtrArray *devices;
	int devices_idx;
	GError *error = NULL;

	/* Default timeout for waiting for operation completion */
	nmc->timeout = 90;

	/* Get the first compulsory argument (SSID or BSSID) */
	if (argc > 0) {
		param_user = *argv;
		bssid1_arr = nm_utils_hwaddr_atoba (param_user, ARPHRD_ETHER);

		argc--;
		argv++;
	} else {
		g_string_printf (nmc->return_text, _("Error: SSID or BSSID are missing."));
		nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		goto error;
	}

	/* Get the rest of the parameters */
	while (argc > 0) {
		if (strcmp (*argv, "iface") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			iface = *argv;
		} else if (strcmp (*argv, "bssid") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
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
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			password = *argv;
		} else if (strcmp (*argv, "wep-key-type") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
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
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			con_name = *argv;
		} else if (strcmp (*argv, "--private") == 0) {
			private = TRUE;
		} else if (strcmp (*argv, "--nowait") == 0) {
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

	if (!nmc_versions_match (nmc))
		goto error;

	nmc->get_client (nmc);
	devices = nm_client_get_devices (nmc->client);

	/* Find a device to activate the connection on */
	devices_idx = 0;
	device = find_wifi_device_by_iface (devices, iface, &devices_idx);

	if (!device) {
		if (iface)
			g_string_printf (nmc->return_text, _("Error: Device '%s' is not a Wi-Fi device."), iface);
		else
			g_string_printf (nmc->return_text, _("Error: No Wi-Fi device found."));
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
		goto error;
	}

	/* Find an AP to connect to */
	ap = find_ap_on_device (device, bssid1_arr, bssid1_arr ? NULL : param_user);
	if (!ap && !iface) {
		/* AP not found. iface was not specified, so try finding the AP on another device. */
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
		nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
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
	if (password) {
		NM80211ApFlags flags = nm_access_point_get_flags (ap);
		NM80211ApSecurityFlags wpa_flags = nm_access_point_get_wpa_flags (ap);
		NM80211ApSecurityFlags rsn_flags = nm_access_point_get_rsn_flags (ap);

		s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wsec));

		/* Set password for WEP or WPA-PSK. */
		if (flags & NM_802_11_AP_FLAGS_PRIVACY) {
			if (wpa_flags == NM_802_11_AP_SEC_NONE && rsn_flags == NM_802_11_AP_SEC_NONE) {
				/* WEP */
				nm_setting_wireless_security_set_wep_key (s_wsec, 0, password);
				g_object_set (G_OBJECT (s_wsec),
				              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE,
				              wep_passphrase ? NM_WEP_KEY_TYPE_PASSPHRASE: NM_WEP_KEY_TYPE_KEY,
				              NULL);
			} else if (   !(wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
				   && !(rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)) {
				/* WPA PSK */
				g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_PSK, password, NULL);
			}
		}
		// FIXME: WPA-Enterprise is not supported yet.
		// We are not able to determine and fill all the parameters for
		// 802.1X authentication automatically without user providing
		// the data. Adding nmcli options for the 8021x setting would
		// clutter the command. However, that could be solved later by
		// implementing add/edit connections support for nmcli.
	}

	/* nowait_flag indicates user input. should_wait says whether quit in start().
	 * We have to delay exit after add_and_activate_cb() is called, even if
	 * the user doesn't want to wait, in order to give NM time to check our
	 * permissions. */
	nmc->nowait_flag = !wait;
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
		} else {
			g_string_printf (nmc->return_text, _("Error: 'dev wifi' command '%s' is not valid."), *argv);
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

	nsps = nm_device_wimax_get_nsps (NM_DEVICE_WIMAX (device));
	for (i = 0; nsps && i < nsps->len; i++) {
		NMWimaxNsp *nsp = g_ptr_array_index (nsps, i);

		detail_wimax_nsp (nsp, nmc, device, idx++);
	}
}

static NMCResultCode
do_device_wimax_list (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;
	NMDevice *device = NULL;
	NMWimaxNsp *nsp = NULL;
	const char *iface = NULL;
	const char *nsp_user = NULL;
	const GPtrArray *devices;
	const GPtrArray *nsps;
	int i, j;
	char *fields_str;
	char *fields_all =    NMC_FIELDS_DEV_WIMAX_LIST_ALL;
	char *fields_common = NMC_FIELDS_DEV_WIMAX_LIST_COMMON;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	while (argc > 0) {
		if (strcmp (*argv, "iface") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			iface = *argv;
		} else if (strcmp (*argv, "nsp") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
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

	nmc->allowed_fields = nmc_fields_dev_wimax_list;
	nmc->print_fields.indices = parse_output_fields (fields_str, nmc->allowed_fields, &error);

	if (error) {
		if (error->code == 0)
			g_string_printf (nmc->return_text, _("Error: 'dev wimax': %s"), error->message);
		else
			g_string_printf (nmc->return_text, _("Error: 'dev wimax': %s; allowed fields: %s"), error->message, NMC_FIELDS_DEV_WIMAX_LIST_ALL);
		g_error_free (error);
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

	if (!nmc_versions_match (nmc))
		goto error;

	/* Print headers */
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_MAIN_HEADER_ADD | NMC_PF_FLAG_FIELD_NAMES;
	nmc->print_fields.header_name = _("WiMAX NSP list");

	nmc->get_client (nmc);
	devices = nm_client_get_devices (nmc->client);
	if (iface) {
		/* Device specified - list only NSPs of this interface */
		for (i = 0; devices && (i < devices->len); i++) {
			NMDevice *candidate = g_ptr_array_index (devices, i);
			const char *dev_iface = nm_device_get_iface (candidate);

			if (!strcmp (dev_iface, iface)) {
				device = candidate;
				break;
			}
		}

		if (!device) {
			g_string_printf (nmc->return_text, _("Error: Device '%s' not found."), iface);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			goto error;
		}

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
					nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
					goto error;
				}
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */
				detail_wimax_nsp (nsp, nmc, device, 1);
			} else {
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */
				show_nsp_info (device, nmc);
			}
		} else {
			g_string_printf (nmc->return_text, _("Error: Device '%s' is not a WiMAX device."), iface);
			nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
			goto error;
		}
	} else {
		/* List NSPs for all devices */
		print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */
		if (nsp_user) {
			/* Specific NSP requested - list only that */
			for (i = 0; devices && (i < devices->len); i++) {
				NMDevice *dev = g_ptr_array_index (devices, i);
				int idx = 1;

				if (!NM_IS_DEVICE_WIMAX (dev))
					continue;

				nsps = nm_device_wimax_get_nsps (NM_DEVICE_WIMAX (dev));
				for (j = 0, nsp = NULL; nsps && (j < nsps->len); j++) {
					NMWimaxNsp *candidate_nsp = g_ptr_array_index (nsps, j);
					const char *candidate_name = nm_wimax_nsp_get_name (candidate_nsp);
					char *nsp_up;

					nsp_up = g_ascii_strup (nsp_user, -1);
					if (!strcmp (nsp_up, candidate_name)) {
						nsp = candidate_nsp;
						detail_wimax_nsp (nsp, nmc, dev, idx);
					}
					g_free (nsp_up);
				}
			}
			if (!nsp) {
				g_string_printf (nmc->return_text, _("Error: Access point with nsp '%s' not found."), nsp_user);
				nmc->return_value = NMC_RESULT_ERROR_UNKNOWN;
				goto error;
			}
		} else {
			for (i = 0; devices && (i < devices->len); i++) {
				NMDevice *dev = g_ptr_array_index (devices, i);
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
			g_string_printf (nmc->return_text, _("Error: 'dev wimax' command '%s' is not valid."), *argv);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
		}
	}

	return nmc->return_value;
}
#endif

NMCResultCode
do_devices (NmCli *nmc, int argc, char **argv)
{
	GError *error = NULL;

	if (argc == 0) {
		if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
			goto opt_error;
		nmc->return_value = do_devices_status (nmc, 0, NULL);
	}

	if (argc > 0) {
		if (matches (*argv, "status") == 0) {
			if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
				goto opt_error;
			nmc->return_value = do_devices_status (nmc, argc-1, argv+1);
		}
		else if (matches (*argv, "list") == 0) {
			if (!nmc->mode_specified)
				nmc->multiline_output = TRUE;  /* multiline mode is default for 'dev list' */
			nmc->return_value = do_devices_list (nmc, argc-1, argv+1);
		}
		else if (matches (*argv, "disconnect") == 0) {
			nmc->return_value = do_device_disconnect (nmc, argc-1, argv+1);
		}
		else if (matches (*argv, "wifi") == 0) {
			if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
				goto opt_error;
			nmc->return_value = do_device_wifi (nmc, argc-1, argv+1);
		}
#if WITH_WIMAX
		else if (matches (*argv, "wimax") == 0) {
			if (!nmc_terse_option_check (nmc->print_output, nmc->required_fields, &error))
				goto opt_error;
			nmc->return_value = do_device_wimax (nmc, argc-1, argv+1);
		}
#endif
		else if (strcmp (*argv, "help") == 0) {
			usage ();
		}
		else {
			g_string_printf (nmc->return_text, _("Error: 'dev' command '%s' is not valid."), *argv);
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
