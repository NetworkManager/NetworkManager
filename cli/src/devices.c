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
 * (C) Copyright 2010 - 2011 Red Hat, Inc.
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>
#include <glib/gi18n.h>

#include <nm-client.h>
#include <nm-device.h>
#include <nm-device-ethernet.h>
#include <nm-device-wifi.h>
#include <nm-device-modem.h>
#include <nm-device-bt.h>
//#include <nm-device-olpc-mesh.h>
#if WITH_WIMAX
#include <nm-device-wimax.h>
#endif
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

#include "utils.h"
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
	{"IP4-SETTINGS",      N_("IP4-SETTINGS"),      0, NULL, 0},  /* 7 */
	{"IP4-DNS",           N_("IP4-DNS"),           0, NULL, 0},  /* 8 */
	{"IP6-SETTINGS",      N_("IP6-SETTINGS"),      0, NULL, 0},  /* 9 */
	{"IP6-DNS",           N_("IP6-DNS"),           0, NULL, 0},  /* 10 */
	{NULL,                NULL,                    0, NULL, 0}
};
#if WITH_WIMAX
#define NMC_FIELDS_DEV_LIST_SECTIONS_ALL     "GENERAL,CAPABILITIES,WIFI-PROPERTIES,AP,WIRED-PROPERTIES,WIMAX-PROPERTIES,NSP,IP4-SETTINGS,IP4-DNS,IP6-SETTINGS,IP6-DNS"
#define NMC_FIELDS_DEV_LIST_SECTIONS_COMMON  "GENERAL,CAPABILITIES,WIFI-PROPERTIES,AP,WIRED-PROPERTIES,WIMAX-PROPERTIES,NSP,IP4-SETTINGS,IP4-DNS,IP6-SETTINGS,IP6-DNS"
#else
#define NMC_FIELDS_DEV_LIST_SECTIONS_ALL     "GENERAL,CAPABILITIES,WIFI-PROPERTIES,AP,WIRED-PROPERTIES,IP4-SETTINGS,IP4-DNS,IP6-SETTINGS,IP6-DNS"
#define NMC_FIELDS_DEV_LIST_SECTIONS_COMMON  "GENERAL,CAPABILITIES,WIFI-PROPERTIES,AP,WIRED-PROPERTIES,IP4-SETTINGS,IP4-DNS,IP6-SETTINGS,IP6-DNS"
#endif

/* Available fields for 'dev list' - GENERAL part */
static NmcOutputField nmc_fields_dev_list_general[] = {
	{"NAME",       N_("NAME"),        10, NULL, 0},  /* 0 */
	{"DEVICE",     N_("DEVICE"),      10, NULL, 0},  /* 1 */
	{"TYPE",       N_("TYPE"),        17, NULL, 0},  /* 2 */
	{"DRIVER",     N_("DRIVER"),      10, NULL, 0},  /* 3 */
	{"HWADDR",     N_("HWADDR"),      19, NULL, 0},  /* 4 */
	{"STATE",      N_("STATE"),       14, NULL, 0},  /* 5 */
	{NULL,         NULL,               0, NULL, 0}
};
#define NMC_FIELDS_DEV_LIST_GENERAL_ALL     "NAME,DEVICE,TYPE,DRIVER,HWADDR,STATE"
#define NMC_FIELDS_DEV_LIST_GENERAL_COMMON  "NAME,DEVICE,TYPE,DRIVER,HWADDR,STATE"

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

/* Available fields for 'dev list' - IPv4 settings part */
static NmcOutputField nmc_fields_dev_list_ip4_settings[] = {
	{"NAME",       N_("NAME"),        15, NULL, 0},  /* 0 */
	{"ADDRESS",    N_("ADDRESS"),     15, NULL, 0},  /* 1 */
	{"PREFIX",     N_("PREFIX"),      20, NULL, 0},  /* 2 */
	{"GATEWAY",    N_("GATEWAY"),     20, NULL, 0},  /* 3 */
	{NULL,         NULL,               0, NULL, 0}
};
#define NMC_FIELDS_DEV_LIST_IP4_SETTINGS_ALL     "NAME,ADDRESS,PREFIX,GATEWAY"
#define NMC_FIELDS_DEV_LIST_IP4_SETTINGS_COMMON  "NAME,ADDRESS,PREFIX,GATEWAY"

/* Available fields for 'dev list' - IPv6 settings part */
static NmcOutputField nmc_fields_dev_list_ip6_settings[] = {
	{"NAME",       N_("NAME"),        15, NULL, 0},  /* 0 */
	{"ADDRESS",    N_("ADDRESS"),     15, NULL, 0},  /* 1 */
	{"PREFIX",     N_("PREFIX"),      20, NULL, 0},  /* 2 */
	{"GATEWAY",    N_("GATEWAY"),     20, NULL, 0},  /* 3 */
	{NULL,         NULL,               0, NULL, 0}
};
#define NMC_FIELDS_DEV_LIST_IP6_SETTINGS_ALL     "NAME,ADDRESS,PREFIX,GATEWAY"
#define NMC_FIELDS_DEV_LIST_IP6_SETTINGS_COMMON  "NAME,ADDRESS,PREFIX,GATEWAY"

/* Available fields for 'dev list' - IPv4 settings DNS part */
static NmcOutputField nmc_fields_dev_list_ip4_dns[] = {
	{"NAME",       N_("NAME"),        15, NULL, 0},  /* 0 */
	{"DNS",        N_("DNS"),         17, NULL, 0},  /* 1 */
	{NULL,         NULL,               0, NULL, 0}
};
#define NMC_FIELDS_DEV_LIST_IP4_DNS_ALL     "NAME,DNS"
#define NMC_FIELDS_DEV_LIST_IP4_DNS_COMMON  "NAME,DNS"

/* Available fields for 'dev list' - IPv6 settings DNS part */
static NmcOutputField nmc_fields_dev_list_ip6_dns[] = {
	{"NAME",       N_("NAME"),        15, NULL, 0},  /* 0 */
	{"DNS",        N_("DNS"),         17, NULL, 0},  /* 1 */
	{NULL,         NULL,               0, NULL, 0}
};
#define NMC_FIELDS_DEV_LIST_IP6_DNS_ALL     "NAME,DNS"
#define NMC_FIELDS_DEV_LIST_IP6_DNS_COMMON  "NAME,DNS"

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


/* static function prototypes */
static void usage (void);
static const char *device_state_to_string (NMDeviceState state);
static NMCResultCode do_devices_status (NmCli *nmc, int argc, char **argv);
static NMCResultCode do_devices_list (NmCli *nmc, int argc, char **argv);
static NMCResultCode do_device_disconnect (NmCli *nmc, int argc, char **argv);
static NMCResultCode do_device_wifi (NmCli *nmc, int argc, char **argv);
#if WITH_WIMAX
static NMCResultCode do_device_wimax (NmCli *nmc, int argc, char **argv);
#endif

extern GMainLoop *loop;   /* glib main loop variable */

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
	         "  wifi [list [iface <iface>] [hwaddr <hwaddr>]]\n"
#if WITH_WIMAX
	         "  wimax [list [iface <iface>] [nsp <name>]]\n\n"
#endif
	         ));
}

/* quit main loop */
static void
quit (void)
{
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
//	case NM_DEVICE_TYPE_OLPC_MESH:
//		return NM_SETTING_OLPC_MESH_SETTING_NAME;
#if WITH_WIMAX
	case NM_DEVICE_TYPE_WIMAX:
		return NM_SETTING_WIMAX_SETTING_NAME;
#endif
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

static gchar *
ip4_address_as_string (guint32 ip)
{
	struct in_addr tmp_addr;
	char buf[INET_ADDRSTRLEN+1];

	memset (&buf, '\0', sizeof (buf));
	tmp_addr.s_addr = ip;

	if (inet_ntop (AF_INET, &tmp_addr, buf, INET_ADDRSTRLEN)) {
		return g_strdup (buf);
	} else {
		g_warning (_("%s: error converting IP4 address 0x%X"),
		            __func__, ntohl (tmp_addr.s_addr));
		return NULL;
	}
}

static gchar *
ip6_address_as_string (const struct in6_addr *ip)
{
	char buf[INET6_ADDRSTRLEN];

	memset (&buf, '\0', sizeof (buf));

	if (inet_ntop (AF_INET6, ip, buf, INET6_ADDRSTRLEN)) {
		return g_strdup (buf);
	} else {
		int j;
		GString *ip6_str = g_string_new (NULL);
		g_string_append_printf (ip6_str, "%02X", ip->s6_addr[0]);
		for (j = 1; j < 16; j++)
			g_string_append_printf (ip6_str, " %02X", ip->s6_addr[j]);
		g_warning ("%s: error converting IP6 address %s",
		           __func__, ip6_str->str);
		g_string_free (ip6_str, TRUE);
		return NULL;
	}
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
	const char *hwaddr;
	NM80211Mode mode;
	char *freq_str, *ssid_str, *bitrate_str, *strength_str, *wpa_flags_str, *rsn_flags_str;
	GString *security_str;
	char *ap_name;

	if (info->active_bssid) {
		const char *current_bssid = nm_access_point_get_hw_address (ap);
		if (current_bssid && !strcmp (current_bssid, info->active_bssid))
			active = TRUE;
	}

	/* Get AP properties */
	flags = nm_access_point_get_flags (ap);
	wpa_flags = nm_access_point_get_wpa_flags (ap);
	rsn_flags = nm_access_point_get_rsn_flags (ap);
	ssid = nm_access_point_get_ssid (ap);
	hwaddr = nm_access_point_get_hw_address (ap);
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
	info->nmc->allowed_fields[2].value = hwaddr;
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
	char *tmp;
	const char *hwaddr = NULL;
	NMDeviceState state = NM_DEVICE_STATE_UNKNOWN;
	NMDeviceCapabilities caps;
	guint32 speed;
	char *speed_str = NULL;
	const GArray *array;
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

		state = nm_device_get_state (device);

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

			nmc->allowed_fields[0].value = nmc_fields_dev_list_sections[0].name;  /* "GENERAL"*/
			nmc->allowed_fields[1].value = nm_device_get_iface (device);
			nmc->allowed_fields[2].value = device_type_to_string (device);
			nmc->allowed_fields[3].value = nm_device_get_driver (device) ? nm_device_get_driver (device) : _("(unknown)");
			nmc->allowed_fields[4].value = hwaddr ? hwaddr : _("unknown)");
			nmc->allowed_fields[5].value = device_state_to_string (state);

			nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
			print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */
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
					active_bssid = active_ap ? nm_access_point_get_hw_address (active_ap) : NULL;
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

		/* IP Setup info */
		if (state == NM_DEVICE_STATE_ACTIVATED) {
			NMIP4Config *cfg4 = nm_device_get_ip4_config (device);
			NMIP6Config *cfg6 = nm_device_get_ip6_config (device);
			GSList *iter;

			/* IP4-SETTINGS */
			if (cfg4 && !strcasecmp (nmc_fields_dev_list_sections[section_idx].name, nmc_fields_dev_list_sections[7].name)) {
				nmc->allowed_fields = nmc_fields_dev_list_ip4_settings;
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
				nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_DEV_LIST_IP4_SETTINGS_ALL, nmc->allowed_fields, NULL);
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

				for (iter = (GSList *) nm_ip4_config_get_addresses (cfg4); iter; iter = g_slist_next (iter)) {
					NMIP4Address *addr = (NMIP4Address *) iter->data;
					guint32 prefix = nm_ip4_address_get_prefix (addr);
					char *tmp2;
					char *addr_str, *prefix_str, *gateway_str;

					addr_str = ip4_address_as_string (nm_ip4_address_get_address (addr));

					tmp2 = ip4_address_as_string (nm_utils_ip4_prefix_to_netmask (prefix));
					prefix_str = g_strdup_printf ("%d (%s)", prefix, tmp2);
					g_free (tmp2);

					gateway_str = ip4_address_as_string (nm_ip4_address_get_gateway (addr));

					nmc->allowed_fields[0].value = nmc_fields_dev_list_sections[7].name;  /* "IP4-SETTINGS" */
					nmc->allowed_fields[1].value = addr_str;
					nmc->allowed_fields[2].value = prefix_str;
					nmc->allowed_fields[3].value = gateway_str;

					nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
					print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */
					g_free (addr_str);
					g_free (prefix_str);
					g_free (gateway_str);
				}
				was_output = TRUE;
			}
			/* IP4-DNS */
			if (cfg4 && !strcasecmp (nmc_fields_dev_list_sections[section_idx].name, nmc_fields_dev_list_sections[8].name)) {
				array = nm_ip4_config_get_nameservers (cfg4);
				if (array) {
					int i;

					nmc->allowed_fields = nmc_fields_dev_list_ip4_dns;
					nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
					nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_DEV_LIST_IP4_DNS_ALL, nmc->allowed_fields, NULL);
					print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

					for (i = 0; i < array->len; i++) {
						char *dns_name = g_strdup_printf ("%s%d", nmc_fields_dev_list_sections[8].name, i+1);
						tmp = ip4_address_as_string (g_array_index (array, guint32, i));
						nmc->allowed_fields[0].value = dns_name;  /* "IP4-DNS<num>" */
						nmc->allowed_fields[1].value = tmp;

						nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
						print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */
						g_free (tmp);
						g_free (dns_name);
					}
				}
				was_output = TRUE;
			}

			/* IP6-SETTINGS */
			if (cfg6 && !strcasecmp (nmc_fields_dev_list_sections[section_idx].name, nmc_fields_dev_list_sections[9].name)) {
				nmc->allowed_fields = nmc_fields_dev_list_ip6_settings;
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
				nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_DEV_LIST_IP6_SETTINGS_ALL, nmc->allowed_fields, NULL);
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

				for (iter = (GSList *) nm_ip6_config_get_addresses (cfg6); iter; iter = g_slist_next (iter)) {
					NMIP6Address *addr = (NMIP6Address *) iter->data;
					guint32 prefix = nm_ip6_address_get_prefix (addr);
					char *addr_str, *prefix_str, *gateway_str;

					addr_str = ip6_address_as_string (nm_ip6_address_get_address (addr));

					prefix_str = g_strdup_printf ("%d", prefix);
					gateway_str = ip6_address_as_string (nm_ip6_address_get_gateway (addr));

					nmc->allowed_fields[0].value = nmc_fields_dev_list_sections[9].name;  /* "IP6-SETTINGS" */
					nmc->allowed_fields[1].value = addr_str;
					nmc->allowed_fields[2].value = prefix_str;
					nmc->allowed_fields[3].value = gateway_str;

					nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
					print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */
					g_free (addr_str);
					g_free (prefix_str);
					g_free (gateway_str);
				}
				was_output = TRUE;
			}
			/* IP6-DNS */
			if (cfg6 && !strcasecmp (nmc_fields_dev_list_sections[section_idx].name, nmc_fields_dev_list_sections[10].name)) {
				int i = 1;
				nmc->allowed_fields = nmc_fields_dev_list_ip6_dns;
				nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
				nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_DEV_LIST_IP6_DNS_ALL, nmc->allowed_fields, NULL);
				print_fields (nmc->print_fields, nmc->allowed_fields); /* Print header */

				for (iter = (GSList *) nm_ip6_config_get_nameservers (cfg6); iter; iter = g_slist_next (iter)) {
					char *dns_name = g_strdup_printf ("%s%d", nmc_fields_dev_list_sections[10].name, i++);

					tmp = ip6_address_as_string (iter->data);
					nmc->allowed_fields[0].value = dns_name;  /* "IP6-DNS<num>" */
					nmc->allowed_fields[1].value = tmp;

					nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
					print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */
					g_free (tmp);
					g_free (dns_name);
				}
				was_output = TRUE;
			}
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
		active_bssid = active_ap ? nm_access_point_get_hw_address (active_ap) : NULL;
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
	const char *hwaddr_user = NULL;
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
		} else if (strcmp (*argv, "hwaddr") == 0) {
			if (next_arg (&argc, &argv) != 0) {
				g_string_printf (nmc->return_text, _("Error: %s argument is missing."), *argv);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				goto error;
			}
			hwaddr_user = *argv;
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
			if (hwaddr_user) {
				/* Specific AP requested - list only that */
				aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (device));
				for (j = 0; aps && (j < aps->len); j++) {
					char *hwaddr_up;
					NMAccessPoint *candidate_ap = g_ptr_array_index (aps, j);
					const char *candidate_hwaddr = nm_access_point_get_hw_address (candidate_ap);

					hwaddr_up = g_ascii_strup (hwaddr_user, -1);
					if (!strcmp (hwaddr_up, candidate_hwaddr))
						ap = candidate_ap;
					g_free (hwaddr_up);
				}
				if (!ap) {
				 	g_string_printf (nmc->return_text, _("Error: Access point with hwaddr '%s' not found."), hwaddr_user);
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
		if (hwaddr_user) {
			/* Specific AP requested - list only that */
			for (i = 0; devices && (i < devices->len); i++) {
				NMDevice *dev = g_ptr_array_index (devices, i);

				if (!NM_IS_DEVICE_WIFI (dev))
					continue;

				aps = nm_device_wifi_get_access_points (NM_DEVICE_WIFI (dev));
				for (j = 0; aps && (j < aps->len); j++) {
					char *hwaddr_up;
					NMAccessPoint *candidate_ap = g_ptr_array_index (aps, j);
					const char *candidate_hwaddr = nm_access_point_get_hw_address (candidate_ap);

					hwaddr_up = g_ascii_strup (hwaddr_user, -1);
					if (!strcmp (hwaddr_up, candidate_hwaddr)) {
						ap = candidate_ap;

						info = g_malloc0 (sizeof (APInfo));
						info->nmc = nmc;
						info->index = 1;
						info->active_bssid = NULL;
						info->device = nm_device_get_iface (dev);
						detail_access_point (ap, info);
						g_free (info);
					}
					g_free (hwaddr_up);
				}
			}
			if (!ap) {
			 	g_string_printf (nmc->return_text, _("Error: Access point with hwaddr '%s' not found."), hwaddr_user);
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

static NMCResultCode
do_device_wifi (NmCli *nmc, int argc, char **argv)
{
	if (argc == 0)
		nmc->return_value = do_device_wifi_list (nmc, argc-1, argv+1);
	else if (argc > 0) {
		if (matches (*argv, "list") == 0) {
			nmc->return_value = do_device_wifi_list (nmc, argc-1, argv+1);
		}
		else {
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
			 	g_string_printf (nmc->return_text, _("Error: Access point with hwaddr '%s' not found."), nsp_user);
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
